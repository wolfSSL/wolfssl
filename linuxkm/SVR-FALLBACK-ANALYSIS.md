# SVR-FALLBACK-ANALYSIS

**Subject.** Whether the cryptographic module should keep a mechanism that
switches, while it is running, between two versions of the same algorithm.

**Recommendation.** Remove it from every build intended for certification. Keep
it available in development builds until it can be better evaluated for
vulnerabilities and potential side channel exploitations.

You may be reading this because you followed a `/* See
linuxkm/SVR-FALLBACK-ANALYSIS.md */` marker. There are 175 of them across 28
files, 8 of which are installed public headers. Each marker sits where a comment
used to argue for a run-time fallback between two implementations of one
algorithm. This file is the answer to all of them.

**How to read it.** The executive summary is written for a reader who is not an
engineer. Sections 1 to 3 are the argument and the certification
position. Sections 4 to 13 are the per-file analysis and the measurements.
Section 14 states where the wording here is stronger than the evidence behind
it. Every claim is either quoted from a published source anyone can check, or
labelled as a result that was tested and measured.

---

## Executive summary

### What this is about, in plain terms

Modern processors have two ways to do the same arithmetic: the ordinary way,
using the processor's general-purpose scratch space, and a faster way, using a
separate set of wide scratch registers built for doing many calculations at
once. Those wide registers are called **vector registers**; the instructions
that use them are called **SIMD** ("single instruction, multiple data").

Inside the Linux kernel those registers do not belong to us. They hold whatever
the interrupted program was using. Before our code may touch them it must ask
the operating system to set them aside, and hand them back when finished. The
kernel provides a specific pair of calls for that, and this module wraps them as
`SAVE_VECTOR_REGISTERS` and `RESTORE_VECTOR_REGISTERS` — **the save** and **the
restore** throughout this document.

The operating system is allowed to refuse the save, and does refuse it in
certain situations. This document is about what the module should do when the
answer is no.

### What the fallback did

When the save failed, the module did not report a failure. It quietly ran a
second, slower version of the same algorithm, written in plain C, and returned
success. In the source that mechanism is controlled by the build setting
`WC_C_DYNAMIC_FALLBACK`.

### The three findings

**1. The failures it was built to survive were ours, not the operating
system's.** The module contained a hand-written rule that refused the vector
registers whenever the running task had process number zero. Process zero is the
idle task, and the kernel runs deferred timer work on the idle task as a matter
of routine — so the module was refusing itself in exactly the situation the
second implementation existed to survive. The kernel's own rule for the same
question contains no test of process identity at all. Deleting our extra
condition resolved the hang. See section 2.

**2. It let an outsider choose which version of the algorithm encrypted their
data, and told nobody.** Whether the save succeeds depends on how busy the
machine is, and system load is something an outside party can influence without
any cryptographic attack. The two versions did not have the same security
properties: the fast one is constant-time, the plain C one performed table
lookups whose addresses depended on the key. The switch could happen part way
through, on the same key, and the call returned success either way. See
section 2.1.

**3. It returns success without having done the work, and this was measured.**
With the save forced to fail, an approved RSA-2048 signature verification on
stock upstream code returns 0, meaning success. On the corrected code it returns
an error. See section 12.2.

### What removal costs

When the save fails, an operation now fails where it previously completed by
another route. That is a real reduction in availability and it is stated here
rather than buried. In the kernel the failure surfaces as an error the caller
can retry. Nothing produces a wrong answer. See section 14 item 14.

### The decision, side by side

| | **Delete the fallback (recommended)** | **Keep it and make it compliant** |
| :--- | :--- | :--- |
| Engineering cost | low — implemented and verified | **many man-days**: new state machine, new public API, 70-90 CASTs, an RFG, possible unknown attack vectors |
| Certification schedule | on track | **+90 days minimum** per RFG turnaround, possibly repeated, possibly refused |
| Security exposure | one constant-time implementation per operating environment | **silent downgrade** to cache-timing-exposed C tables, measured |
| Module classification | Software, Multi-chip Standalone — as validated three times | **risk of re-classification as a Hybrid Module** |

Both cost figures carry qualifications and neither should be quoted without
them. wolfSSL's own estimate less the RFG is 46-70 man-days (section 3.2) and assumes the
laboratory's reading of its item 5. The 90-day figure and the hybrid conclusion are
**reported laboratory position, not sourced citations** — see the provenance
note opening section 3.2. The security finding in section 2.1 is measured in
this tree and does not depend on either figure.

### What is still open

This review found the fallback while testing something else, and found
several other issues on the way. It did not go looking for them systematically.

Every issue the solution purported to solve seemed to be anecdotal, not from a
test failing. None of the defensive structures involved had a test log that
showed it despite attempts to procure such evidence. A count of problems found
that way is a count of what one reader noticed, not a measure of what exists.
Section 14 sets out the specific limits.

### Recommendation

1. Remove the run-time fallback from every build intended for certification.
   Keep it in development builds until it can be better evaluated or removed if
   found to be unsafe.
2. Keep selecting the fast version from what the processor reports it supports.
   That is a different mechanism with different consequences, and it is what the
   previously validated modules shipped. See section 3.0.
3. Take the open certification question in section 3.1.1 to the laboratory
   before submission.
4. Commission a deliberate audit along the lines of Appendix A rather than
   continuing to find these by accident.

---

## 1. The rule

1. **We support the operating environment. We do not redesign it.** The
   operating environment — a named kernel on named hardware, listed on the
   certificate — is what we build *within*. Its refusals are boundary
   conditions, not bugs to route around.
2. **One implementation per algorithm executes per operating environment, and
   processor capability alone decides which.** A write-once CPUID read at first
   use, never revised (section 3.0). Nothing else may influence the choice.
3. **When the selected implementation cannot run, return an error.** Never run a
   different implementation. `SAVE_VECTOR_REGISTERS2()` returning non-zero is a
   result to propagate, not a condition to work around.

---

## 2. What was here before, and why it was wrong

The old approach wanted to ship **two implementations of one algorithm** — one using
vector registers, one not — and pick between them at run time. If
`SAVE_VECTOR_REGISTERS2()` failed, the C twin ran and returned success. The
switch could happen mid-operation, call to call.

### 2.0.1 Why it was built

1. **Improper insertion point.** The DRBG was registered as the systemwide
   `stdrng`, which wired it into deferred interrupt work (softirq). The kernel's
   crypto-API RNG service was never designed for that context.
   `crypto/drbg.c:drbg_generate_long()` wraps every generate in a sleeping lock
   (`struct mutex drbg_mutex`, `include/crypto/drbg.h:115`), and
   `crypto/rng.c:crypto_get_default_rng()` — the only route to that service —
   takes one too. A sleeping lock cannot be taken in softirq. That was readable
   before any of this was written.
2. **Failures followed**, as they had to.
3. **Instead of correcting the insertion point, a fallback was invented** to
   survive the failures: a second implementation, selected at run time.
4. **The fallback solved a problem that only existed because of step 1**, and
   created a compliance concern doing it.

Remove the improper insertion and the fallback has nothing left to do.

### 2.0.2 The specific failure blamed on the operating system was ours

A kernel DRBG hang — module spinning in softirq, `FIPS_MODE_FAILED`, 62,915
errors over 29.7 s, a 28.9 s clocksource stall — traced to one line in
`linuxkm/x86_vector_register_glue.c`:

```c
if (((preempt_count() & (NMI_MASK | HARDIRQ_MASK)) != 0) ||
    (task_pid_nr(current) == 0))
    return 0;   /* vector registers refused */
```

`task_pid_nr(current) == 0` refuses on the idle task, and timer softirqs run on
the idle task. The module was refusing itself, every time, in exactly the
situation the C twin existed to survive. The reason was bookkeeping, not safety:
the per-CPU slot table used pid 0 as its "slot free" marker, which made the idle
task impossible to represent.

The kernel's own rule, `irq_fpu_usable()`
(`arch/x86/kernel/fpu/core.c`), has **no task-identity or pid condition
anywhere**:

```c
    if (!in_hardirq())
        return true;
    return !softirq_count();
```

On x86, `may_use_simd()` is defined to be exactly `irq_fpu_usable()`
(`arch/x86/include/asm/simd.h`). Our condition was a locally invented
substitute, stricter than the rule it replaced.

**How it was fixed.** The "slot free" marker moved to its own `in_use` field so
pid 0 is representable, and the `pid == 0` condition was deleted. The
module now applies the operating environment's actual rule.

**Result.** Timer softirq 0/2 → 2/2; the module stays in `FIPS_MODE_NORMAL`,
verified under `CONFIG_PROVE_LOCKING` and `CONFIG_DEBUG_ATOMIC_SLEEP`.
Reinstating only that line reproduces the failure at 61,458 errors. "It can
never work in softirq" was measurable, was measured, and is false.

NMI and hardirq context are still refused, for a stated reason: this function
brackets with `local_bh_disable()` / `local_bh_enable()`, and
`kernel/softirq.c:__local_bh_enable_ip()` opens with `WARN_ON_ONCE(in_hardirq())`
and `lockdep_assert_irqs_enabled()`. That bracket is illegal there. It is the
same line the operating environment's own crypto drivers draw.

---

## 2.1 The security property the fallback removes — read this first

**This is the strongest argument against the fallback and it does not depend on
any reading of the Implementation Guidance.** Section 3 is a compliance argument
a laboratory can debate. This one is a security property, it is externally
influenceable, and it is created purely by the fallback mechanism itself.

### 2.1.1 The two implementations do not have the same security properties

| | data-dependent memory access | timing |
|---|---|---|
| AES-NI (`aesenc`/`aesdec`) | none — the round is a single instruction | constant |
| the C twin | `Te[4][256]` T-table and S-box lookups **indexed by key-dependent state** | key-dependent |

Read directly from the source, not inferred: `wolfcrypt/src/aes.c:2006` declares
`static const FLASH_QUALIFIER word32 Te[4][256]`, the classic four-table AES.
Which table entries are read determines which parts of the processor's cache are
touched, and that is observable by another program on the same machine. This is
not a theoretical concern; it is one of the best-documented attacks on software
AES:

* Bernstein, *Cache-timing attacks on AES* (2005) —
  https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
* Osvik, Shamir and Tromer, *Cache attacks and countermeasures: the case of AES*
  (2006) — https://eprint.iacr.org/2005/271

### 2.1.2 What the fallback does with that

`SAVE_VECTOR_REGISTERS2()` failing is not a rare hardware event. It is a
*context* condition — softirq pressure, nested vector-register sections, atomic
context. Therefore:

1. **An adversary who can influence system load can influence which
   implementation encrypts their peer's data.** Creating conditions where the
   vector registers are unavailable is not a cryptographic attack; it is
   scheduling pressure.
2. **The switch is per operation, mid-stream, on the same key.** A single key's
   traffic can be encrypted partly by a constant-time implementation and partly
   by a cache-timing-exposed one.
3. **No indicator tells the Cryptographic Officer it happened.** The call returns
   success either way. There is no status output distinguishing the two, so the
   downgrade is not observable, not loggable, and not attributable afterwards.

An attacker does not have to break AES-NI. They have to make it unavailable, and
the module hands them the weaker implementation on the same key without saying
so.

### 2.1.3 The software AES was hardened independently

**The issue.** The C AES was compiled with its cache-line countermeasure off.
`WOLFSSL_AES_TOUCH_LINES` (documented at `aes.c:92`, *"Touch all cache lines for
side-channel resistance"*, **default: off**) was set nowhere in `configure.ac`,
`settings.h`, `linuxkm/`, or the generated `wolfssl/options.h` of any build here.
A weaker mitigation was compiled — `PreFetchTe()` (`aes.c:2699`, guarded by
`#ifndef WC_NO_CACHE_RESISTANT`, which is on by default, and called at
`aes.c:3046`) — but it touches the tables once per operation rather than per
round, so it does not make the C AES constant-time.

**The fix.** `linuxkm/linuxkm_wc_port.h` now defines `WOLFSSL_AES_TOUCH_LINES`
for every FIPS linuxkm build, unless `WC_NO_CACHE_RESISTANT` is already set. The
same block raises a `#warning` naming what a customer gives up if they do set
it. Verified by object comparison rather than by reading the edit: `aes.o` is
258,160 bytes with the change and 245,568 without.

This was worth doing on its own merits. Under the elected posture, processor
capability can still select the C lane on a part without AES-NI, so the T-table
exposure survives the fallback's removal on such an operating environment.

**Result — the performance cost.** Cycles per byte, AES-256, Core Ultra 9 285K,
userspace `--enable-fips=v7`:

| mode | T-tables (leaky) | touch-lines | bitsliced |
| :--- | ---: | ---: | ---: |
| CTR | 8.95 | 201.41 | 19.93 |
| CBC-dec | 8.16 | 203.41 | 19.96 |
| GCM-enc | 15.39 | 208.74 | 26.40 |
| GCM-dec | 16.46 | 209.14 | 27.45 |
| CBC-**enc** | 9.03 | **202.62** | 1199.92 |
| CFB-enc | 9.15 | 206.60 | 1206.61 |
| CFB-dec | 8.22 | 205.69 | 1207.73 |
| OFB-enc | 9.02 | 205.14 | 1443.50 |
| OFB-dec | 8.98 | 206.65 | 1279.50 |
| AES-128-**CMAC** | — | **145.14** | 1076.86 |
| AES-256-**CMAC** | — | **202.44** | 1196.80 |

**On a part with AES-NI the countermeasure is free.** AES-256-CBC-enc measured
1843.4 MiB/s with it against 1825.6 without — a difference inside the noise and
in the wrong direction. The AES-NI lane never touches the T-tables, so the cost
is paid only where the C lane can actually be selected.

**`WC_AES_BITSLICED` was measured and rejected.** It is 8-10x faster than
touch-lines wherever blocks are independent, and it is structurally table-free
rather than constant-time by construction of an access pattern. But four of the
nine AES modes this module registers chain block to block — `cbc(aes)` encrypt,
`cfb(aes)`, `ofb(aes)`, `cmac(aes)` — and there it is 5.9-7.0x **worse** than
touch-lines. CMAC matters most: it is a FIPS algorithm with its own CAST, so the
regression lands in the module's own self-test path. Touch-lines is uniform
across every mode (205-207 cpb); bitsliced spreads **73x** between its best and
worst, with OFB-enc at 1443.50 the worst mode in the module.

Bitsliced is also not combinable per mode. The T-table core is compiled out
entirely under `#ifndef WC_AES_BITSLICED`, carrying both would cost 122,880
bytes of `bs_key` per `Aes` context, and two AES implementations in the boundary
means two CASTs under IG 10.3.A GeneralNote1. Electing per operating
environment, not per mode, is the shape that keeps one implementation per
algorithm.

### 2.1.4 The three positions a customer can occupy

Stated as a trade rather than a recommendation. AES-256-CBC-enc figures, same
host:

| | AES without PAA | RSA / ECC | OE slots |
| :--- | :--- | :--- | ---: |
| **FIPS default** (touch-lines) | constant-time, 202.6 cpb | blinding + timing resistance | **1** |
| `--disable-harden` | T-tables, 9.0 cpb, **cache-observable** | **blinding and timing resistance OFF** | **1** |
| **PAA** (AES-NI) | constant-time, 1.9 cpb | blinding + timing resistance | **2** |

* **FIPS default.** Safe and slow. One OE slot. This is the position for a
  software-only validation and it is what ships unless the customer says
  otherwise.
* **`--disable-harden`.** Fast and leaky, still one OE slot, and cheaper at the
  laboratory than validating PAA and non-PAA separately. Some customers run
  kernels small enough that no untrusted process is present to observe the
  cache, and for them this is a rational election. **It is not an AES-only
  trade**: `configure.ac:3248-3255` shows `--enable-harden` supplies
  `TFM_TIMING_RESISTANT`, `ECC_TIMING_RESISTANT` and `WC_RSA_BLINDING`, and
  `--disable-harden` withholds all three in addition to setting
  `WC_NO_CACHE_RESISTANT`. A customer electing this for AES throughput also
  gives up RSA blinding and ECC timing resistance. Sell it that way.
* **PAA.** Safe and fast, but the module must be validated on the PAA and
  non-PAA operating environments separately, so it costs two OE slots and two
  sets of laboratory fees rather than one.

Hardening the C implementation does not retire this section's finding. The
objection to the fallback is that an **outside party can choose which
implementation runs**, mid-stream, on a live key, with no indicator to the
operator. A build flag cannot answer that.

### 2.1.5 What removing the fallback actually changes

Be exact, because the looser claim is easy to make and is false. Under the
elected posture the C AES is still compiled — `aes.c:2006` still emits
`Te[4][256]`, and no build in this tree suppresses it. **The T-tables are in the
binary.** What changes is narrower: the C twin is still **compiled** but is no
longer **reachable** from a vector-register save failure. Processor capability alone selects the lane; a
save failure returns `WC_ACCEL_INHIBIT_E`. An attacker who can make the vector
registers unavailable can no longer steer a key's traffic onto the T-table
implementation. The downgrade path is deleted even though the code is not.
Whether *carrying* the unreachable twin is acceptable is the contained-versus-
reachable question of section 3.1.1, and this section does not settle it.

### 2.1.6 Scope, stated honestly

This is an argument about AES, where the two implementations differ in
constant-timeness. It is not a claim that every fallback pair in the tree has a
side-channel difference — SHA-2 and SHA-3 are not table-driven in the same way,
and their fallback problem is the one in sections 3, 6 and 7. Nor is it a
measured attack: no cache-timing exploit was run against the C path here. What
is established by reading is that the module contains a table-driven AES, that a
context condition an external party can influence selects it, and that nothing
reports the selection.

---

## 3. What the Implementation Guidance requires, and what we elect

### 3.0 The elected posture

**v7 matches what v5.2.1, v5.2.4 and v6.0.0 shipped.** The run-time kernel
fallback is deleted; selection on processor capability is retained. Two
configure postures, and only two:

1. **Configured with PAA.** Each algorithm may step between its implementations
   **on processor capability alone** — a write-once CPUID selection made at
   first use and never revised (section 3.1.1). **No kernel fallback**: a
   vector-register save failure returns an error to the caller. It must never be
   answered by quietly running a different implementation and reporting success.
2. **Configured without PAA.** Software only. No accelerated lane is compiled.

**What is deleted is the fallback, not the stepping.** These are two different
mechanisms with different consequences:

| | Selected by | When | Reachable per OE | Status |
|---|---|---|---|---|
| Processor-capability stepping | CPUID, write-once | first use | **1** | **retained** — as in v5.2.1 / v5.2.4 / v6.0.0 |
| Kernel fallback | save failure | any call | **2** | **deleted** — sections 2.1, 12.5 |

The fallback is the mechanism that lets an external party choose between two
implementations mid-stream on one key with no indicator (section 2.1), and that
converts an observable failure into a silent wrong answer (section 12.5).
Neither objection touches CPUID stepping, because stepping is fixed for the life
of the module on a given processor and is not influenced by anything an attacker
controls.

**This posture carries no hybrid-embodiment risk and needs no RFG**, because it
contains no run-time toggle of any kind: the PAA / software-only choice is made
at configure time, and processor stepping is a write-once read of the processor
with no operator input. The hybrid question and its 90-day RFG belong to the
alternative, which requires a lane-selection mechanism in order to test each
implementation. Section 3.2.1 has the verification and the citation.

**What this posture depends on, stated plainly.** It requires the *reachable*
reading of the CAST obligation (section 3.1.1): one lane executes per operating
environment, so one CAST per algorithm is correct even though several lanes are
compiled in. The precedent is strong — v5.2.1, v5.2.4 and v6.0.0 were all
validated carrying exactly this construct (section 3.4.1). But the reading has
**not** been put to Aegisolve, and IG 10.3.B Additional Comments 1 is the text
that must be answered. **Settle it with the laboratory before submission.** If
the laboratory insists on the *contained* reading, the two remaining options are
a CAST per compiled implementation (the 70-90 CAST set), or shipping posture 2 —
configured without PAA, where one implementation is compiled and there is
nothing extra to test — at the cost of the acceleration. Neither requires a new
selection mechanism.

**Three mechanisms enforce this posture and must not be mistaken for casualties
of it:**

* the **fallback prohibition** — the `#error` on `WC_C_DYNAMIC_FALLBACK` in
  `wolfssl/wolfcrypt/settings.h` and `wolfssl/wolfcrypt/fips.h`, plus
  `WC_ALLOW_RUNTIME_IMPL_SELECT` being undefined in a certified build. That is
  the decision, not a casualty of it.
* the **shim-layer fallback prohibition** — the `#error` on
  `WC_LINUXKM_C_FALLBACK_IN_SHIMS` in `linuxkm/lkcapi_glue.c`. This is a
  *second, independent* fallback mechanism, in the LKCAPI glue rather than in
  wolfCrypt, and it must be named rather than left for a reviewer to find. It
  keeps a separately-keyed C AES context beside the accelerated one and selects
  it in `km_AesGet()` (`linuxkm/lkcapi_aes_glue.c`) when the vector registers
  are unavailable:

  ```c
  else if (! CAN_SAVE_VECTOR_REGISTERS()) {
      ret = ctx->aes_decrypt_C;      /* a DIFFERENT implementation */
  }
  ```

  That is the same defect as `WC_C_DYNAMIC_FALLBACK` one layer up, and it
  carries the same second-key-schedule cost that section 8 describes. It guards
  15 sites in `lkcapi_aes_glue.c` and further sites in `lkcapi_sha_glue.c`. Two
  things hold it out of a certified build: the `#error` above, and the
  auto-define beneath it requiring `WC_ALLOW_RUNTIME_IMPL_SELECT`, which no
  validation-targeted build defines. Non-FIPS and uncertified development builds
  (`--enable-fips=dev`, `dev-no-post`) may still enable it.

  **Where it can appear at all.** The mechanism and its guard exist only in
  builds configured with `--enable-linuxkm-lkcapi-register`; `module_hooks.c`
  includes the glue inside `#ifdef LINUXKM_LKCAPI_REGISTER`. Without that option
  none of `lkcapi_glue.c`, `lkcapi_aes_glue.c` or `lkcapi_sha_glue.c` is
  compiled, so the second implementation is absent rather than merely refused.

  **The refusal is demonstrated, not asserted.** Preprocessing `module_hooks.c`
  with the module's own kbuild flags: with `-DLINUXKM_LKCAPI_REGISTER` alone the
  build is clean; adding `-DWC_LINUXKM_C_FALLBACK_IN_SHIMS` fails at
  `lkcapi_glue.c:112` with that `#error`. Both arms were run — a guard that has
  never been seen to fire proves nothing by staying silent.
* the **early-DRBG C selection** (sections 13.1, 13.2). Fixing one hash to C so
  the DRBG is available before the vector unit is usable is an *availability*
  constraint, not a CAST constraint, and it survives unchanged.

ML-KEM and ML-DSA reach the no-fallback behaviour through the files' own
fail-closed macros, `MLKEM_SVR_OR_RETURN()` / `MLDSA_SVR_OR_RETURN()`, which
return the save error instead of selecting a lane. That covers roughly 125
dispatch sites; `scripts/fips-no-svr-fallback-check.sh` reports 0 live fallback
sites in both files.

### 3.0.1 Two things are true at once

1. The Implementation Guidance does not *forbid* carrying multiple
   implementations. Nothing in IG 10.3.A compels a single implementation.
2. The Implementation Guidance *does* require each implementation to be
   self-tested separately, and **this module carries one CAST per algorithm, not
   one per implementation.** Whether that is a gap turns entirely on which
   implementations the obligation reaches — the contained-versus-reachable
   question of section 3.1.1.

**What raises the question is carrying more than one implementation, not the
fallback.** The fallback is the sharpest case, because it lets an external party
pick between implementations mid-stream on the same key. But plain CPUID
dispatch raises the same question with **no fallback compiled at all** — section
12.6's five SHA-512 transforms are selected by `cpuid_get_flags()` in a build
that has never heard of `WC_C_DYNAMIC_FALLBACK`. Deleting the fallback does not,
by itself, reduce how many implementations are compiled in.

**This is not a novel construct invented for v7.** Cert #4718 (module v5.2.1)
was granted carrying exactly it — run-time CPUID-dispatched AES-NI, and a
five-way SHA-512 transform selection — with one CAST per algorithm. Section
3.4.1 verifies that in the frozen v5.2.1 tree and in `140sp4718.pdf`. The
stepping v7 retains is the mechanism the CMVP has already validated in a wolfSSL
module. The run-time fallback is not, and never was.

### 3.1 What the Implementation Guidance actually says

> "If the module contains different implementations (e.g., separate libraries, or
> two instances on the same or different hardware) of a single algorithm in an
> approved mode, each implementation of this algorithm shall be self-tested
> separately."
>
> — FIPS 140-3 IG 10.3.A, General CAST requirements, **GeneralNote1**
> (verified verbatim against the IG dated 16 April 2026)

A **different** section restates it with an example much closer to this module's
situation — **IG 10.3.B, Additional Comments 1**. Note the section number: this
text is *not* in 10.3.A, and citing it as such invites correction.

> "If the cryptographic module contains several core cryptographic algorithm
> implementations (e.g., **several different implementations of SHA-256
> algorithm**) and some are not used by other higher approved cryptographic
> algorithms (and are therefore not self-tested), then the cryptographic module
> must perform a separate self-test for each of those implementations."
>
> — FIPS 140-3 IG 10.3.B, Additional Comments 1

That example matters: "several different implementations of SHA-256 algorithm"
inside one module is exactly what `sha256.c` and `sha512.c` carry (section
12.6), which makes 10.3.B a closer citation than GeneralNote1's "separate
libraries, or two instances on the same or different hardware."

**That is a testing obligation, not a prohibition.** The remedy the sentence
names is *test each one*. It does not say *carry only one*. Any argument that
reads it as forbidding multiple implementations is reading in a conclusion the
text does not support.

The on-point section for acceleration is **IG 2.3.C** (Processor Algorithm
Accelerators and Processor Algorithm Implementation), and it explicitly
contemplates the construct:

> "If the software or firmware component of the module can support a
> cryptographic algorithm natively (within the software/firmware) or by utilizing
> an available PAA or PAI, the module shall be defined as either a Software
> module embodiment or a Firmware module embodiment…"
>
> "Algorithm certificates: the accelerated algorithms **shall be tested in both
> software/firmware only execution and PAA execution.** See CAVP FAQ AES.2."
>
> "Operational Environment: MIS Table Descriptions Table 3 … would include both
> 'yes' and 'no' entries in the column for PAA/PAI…"
>
> — FIPS 140-3 IG 2.3.C, Resolution

So the CMVP describes a module that does the algorithm natively *or* via PAA,
prescribes **testing both** as the remedy, and expects the operating-environment
table to carry both PAA rows. Carrying two implementations is a supported
design. It is not a finding in the abstract.

**Whose reading is whose.** GeneralNote1's own examples are "separate libraries,
or two instances on the same or different hardware." Whether that reaches *two
code paths in one library selected by CPUID* is a live interpretive question,
and this document does not settle it by assertion. What it relies on is (a) IG
10.3.B's "several different implementations of SHA-256 algorithm" example, which
does reach the case squarely, and (b) **Aegisolve's position as of 12 August
2026** (section 3.2), which treats run-time implementation selection as
requiring per-implementation self-test, reporting and control. The
counter-reading — that a CPUID-selected lane is one implementation with variants
— is the one a laboratory would have to be argued out of, and no one has tried.

GeneralNote1 requires one self-test *per implementation*. This module has one
CAST *per algorithm*:

```c
/* wolfssl/wolfcrypt/fips_test.h */
FIPS_CAST_AES_CBC           =  0,
FIPS_CAST_AES_GCM           =  1,
FIPS_CAST_AES_ECB           = 19,
...
FIPS_CAST_COUNT             = 29
```

There is no `FIPS_CAST_AES_CBC_AESNI` beside a `FIPS_CAST_AES_CBC_C`. Counting
the lanes **compiled into** an x86_64 build — AES up to 6 (C, AES-NI, AVX1,
AVX2, VAES+AVX2, VAES+AVX512), SHA-256 7, SHA-512 5, SHA-3 3, SP/ECC 3, ML-KEM
up to 8, ML-DSA 4, SLH-DSA 2 — a CAST set covering every one of them is not 26
tests. It is on the order of 70 to 90.

**Read that number for what it counts:** implementations *contained in the
binary*, summed across every processor that could run it. The number
**reachable on any one operating environment is 1** without the fallback and
**2** with it. 70-90 is the ceiling under the strict (contained) reading, not a
measured requirement.

So the accurate statement is not "multiple implementations are allowed, so we
are fine." It is:

* multiple implementations **are** allowed, **if** each is self-tested; and
* this module **does not** self-test each one, so on the contained reading any
  build carrying more than one implementation of an algorithm does not conform —
  with or without the fallback, since CPUID dispatch alone is enough (section
  12.6); and
* conformance under that reading is reachable only by building the
  infrastructure that makes per-implementation testing possible at all. You
  cannot test an implementation separately until you can *say which one ran* and
  *make a chosen one run*.

That last point is the whole cost, and it is what section 3.2 records.

### 3.1.1 Contained versus reachable — the distinction the counting arguments missed

The lane counts above (70-90 CASTs) and section 3.2 item 5's "5x or 6x OEs" both
count implementations *contained in the binary across every processor that could
exist*. That is not the number reachable on any one operating environment, and
an operating environment is what gets validated.

`sha256.c:488` — `sha_method` is a **write-once latch**:

```c
static enum sha_methods sha_method = SHA256_UNSET;

static void Sha256_SetTransform(void)
{
    if (sha_method != SHA256_UNSET)
        return;
    cpuid_get_flags_atomic(&intel_flags);
    ...
}
```

It is set once, from CPUID, and never revised. `inline_XTRANSFORM` then behaves
in one of two ways:

```c
#ifdef WC_C_DYNAMIC_FALLBACK
    if ((sha_method == SHA256_C) || (SAVE_VECTOR_REGISTERS2() != 0))
        return Transform_Sha256_C_from_raw(S, D);  /* silently runs the C lane */
#else
    if (sha_method == SHA256_C) { ... }
    SAVE_VECTOR_REGISTERS(return _svr_ret;);       /* errors out; no other lane */
#endif
```

So, per algorithm, on one operating environment:

| Posture | **Reachable** on one OE | **Contained** in the binary |
|---|---|---|
| Fallback compiled in (the deleted design) | **2** — the CPUID lane, plus C on save failure | 5-7 |
| CPUID stepping, no fallback (this branch; Cert #4718; the industry norm) | **1** | 5-7 |
| Configured without PAA (posture 2, section 3.0) | **1** | 1 |

**No build ever had five reachable lanes on one operating environment — not even
the fallback build.** The fallback adds exactly one reachable implementation,
and it adds it non-deterministically. It does not add four.

**Consequence for the operating-environment count.** An operating environment is
(operating system, processor, platform). IG 2.3.C's acceleration dimension on
MIS Table 3 is binary — PAA/PAI `Yes` or `No`. Neither 2.3.C nor 2.3.A produces
a table row per code lane. Selecting an assembly implementation from CPUID and
shipping the others dead is standard practice and is what Cert #4718 was
validated with. **wolfSSL's position is that lanes are not operating
environments and the ceiling is 2x on PAA-capable platforms** — and that 2x
comes from IG 2.3.C Option 1 (section 3.3), not from lane counting. This is a
dissent from the laboratory's item 5 and is recorded as such.

**Consequence for the CAST count — this is the question that actually matters,
and it is unsettled.** It turns on whether the self-test obligation counts
*contained* or *reachable* implementations:

* **Reachable** — one lane executes per operating environment, so one CAST per
  algorithm is correct, and it is equally correct whether the other lanes are
  compiled in or not. On this reading the fallback is the only thing that must
  go.
* **Contained** — IG 10.3.B Additional Comments 1 is the text to beat, and it is
  uncomfortably on point: a module that "**contains** several core cryptographic
  algorithm implementations … and some **are not used** … must perform a separate
  self-test for each of those implementations." Dead lanes are contained and
  unused. On this reading a CPUID-stepped build needs the 70-90 CAST set, and
  the only alternative is to compile one implementation.

**The argument for *reachable*.** 10.3.B's subject is CAST coverage inheritance
for **embedded** algorithms (SHA-256 inside HMAC and ECDSA), so "not used by
other higher approved cryptographic algorithms" plausibly means "not covered by
the higher algorithm's CAST", not "dead code". An unreachable lane is not an
implementation missing coverage; it is an implementation that never executes.

**Open item, and the one to take to Aegisolve first.** Whether the obligation
counts contained or reachable implementations has **not** been put to the
laboratory. Argue reachability, and argue it from the write-once latch above,
which is demonstrable and testable — not from "everyone does this", which is an
argument about practice rather than about the rule.

**What reachability settles if it wins.** It discharges the CAST obligation for a
CPUID-stepped build, because on any single operating environment exactly one
implementation executes. What remains is section 2.1 — which only ever required
removing the **fallback** — plus a hardening argument that dead vector code sits
inside the integrity boundary. That hardening argument is real, but it is not a
FIPS requirement and must not be presented as one.

### 3.2 What the laboratory requires to keep the fallback (Aegisolve, 12 August 2026)

**Provenance — needed before this section is quoted to anyone.** What follows is
paraphrase, written up from the laboratory's position of 12 August 2026. No
written source document is cited, and several items are specific enough that a
reviewer will ask for one. Item 4 in particular — the fallback may fire
**once**, the failed implementation must **re-run its own CAST** before reuse,
and the module **remains degraded until power cycle or integrity re-run** — is a
precise three-part rule that reads as quotation rather than summary. Item 2's
**90-day** RFG figure and item 6's hybrid conclusion are the same kind of claim.
**Obtain the written wording (email, report section, or meeting minute) and cite
it inline here**; until then treat every numbered item below as "reported
laboratory position", not as a citation.

1. **An implementation-reporting mechanism, and a way to control which lane
   runs.** Per-implementation self-testing is meaningless without both: the
   operational test has to be able to select a lane deterministically and then
   confirm which lane actually executed. Neither exists today. This is new public
   API surface on every accelerated algorithm.

2. **An RFG (Request For Guidance) would be required** to establish whether
   run-time implementation toggling is certifiable at all and still call it a
   "Software Module". Each RFG turnaround carries a **potential 90-day delay**,
   and more than one round trip is possible. The answer may be "no", in which
   case the preceding work is spent for nothing.

3. **Successes may no longer be reported where a failure occurred.** The present
   behaviour — a lane fails, another lane silently produces an answer, the
   operator sees success — is not acceptable. This is the same defect section
   12.5 demonstrates by measurement, arrived at independently by the laboratory.

4. **A fallback event must be treated as entry into a degraded mode of
   operation.** Specifically: the fallback may fire **once**; the implementation
   that failed must then **re-run its own CAST** before it may be used again;
   and the module must **remain in degraded mode until power cycled or the
   integrity test is re-run**. The module's current design has no
   per-implementation CAST state, no per-implementation degraded mode, and no
   such latch. This is a redesign of the finite state machine core, not an
   addition to it.

5. **A separate operating environment must be tested for every possible lane and
   fallback combination.** The matrix does not grow by a row or two; it
   multiplies by the lane count of every algorithm on that platform. Instead of
   2x operating environments, PAA customers may face 5x or 6x.

   > **wolfSSL dissents from this item and expects to prevail on it.** An
   > operating environment is (operating system, processor, platform); IG
   > 2.3.C's acceleration dimension on MIS Table 3 is binary, `Yes` or `No`.
   > Neither 2.3.C nor 2.3.A produces a table row per code lane, and section
   > 3.1.1 shows the reachable-lane count on any one operating environment is 1
   > without the fallback and 2 with it — never 5. **The ceiling is 2x on
   > PAA-capable platforms**, and that 2x comes from IG 2.3.C Option 1, not from
   > lane counting.
   >
   > Note what this dissent does **not** touch: the *CAST* obligation. Whether a
   > dead lane needs its own CAST is a separate question, it is unsettled, and
   > IG 10.3.B Additional Comments 1 is the text against us. Do not let a win on
   > operating-environment counting be read as a win on CAST counting.

6. **The toggle itself changes the module embodiment.** A mechanism that
   constrains run-time execution to software-only or PAA-only makes this a
   **Hybrid Module**. It could no longer be claimed as *Software — Multi-chip,
   Standalone*. This one is not buyable with engineering effort; it is a
   different validation. **Removing the toggle mechanism removes the hybrid
   risk.**

   > **The laboratory's position on this item, stated precisely.** Aegisolve will
   > not put it in writing, and says that getting the CMVP to put it in writing
   > requires an RFG. The substance, as given verbally: **any kind of run-time
   > toggling** sounds like a hybrid to the laboratory — *including a toggle
   > whose purpose is to disable the fallback at run time*. So this is an
   > unresolved question, not a determination.
   >
   > **IG 2.3.C's text points the other way.** It defines the trigger by
   > operating-environment coverage, not by the presence of a toggle: "A module
   > is considered a hybrid if **all** the Operational Environments (OEs) only
   > support with PAA/PAI and were tested as such." Its Software/Firmware
   > paragraph covers the both-ways case: "If the software or firmware component
   > of the module can support a cryptographic algorithm natively (within the
   > software/firmware) **or** by utilizing an available PAA or PAI, the module
   > shall be defined as either a Software module embodiment or a Firmware module
   > embodiment". The one opening is the trailing clause "**unless other
   > requirements designate the module as hybrid**", which does not say what
   > those requirements are.

7. **The finite state machine expands** to carry the state transitions for every
   implementation's CAST status, its degraded-mode entry, and its re-test path.

8. **Deleting the fallback eliminates every item above.** With the lane fixed by
   CPUID at first use and a save failure returning an error, there is no
   reporting API, no toggle, no RFG, no hybrid embodiment question, no state
   machine expansion, and no per-lane operating-environment multiplication. The
   CAST set stays at one per algorithm because one implementation executes per
   algorithm per operating environment.

### 3.2.1 The hybrid risk attaches to the toggle, and the elected posture has no toggle

The laboratory's concern is run-time toggling. Section 3.0 has none, and that is
verifiable rather than asserted:

* **No run-time knob selects an implementation.** The only kernel module
  parameters are `text_dump_path` and `rodata_dump_path` (`module_hooks.c`, mode
  `0444`, diagnostic file paths). Neither reaches algorithm dispatch.
* **The save-failure fuzzer is build-time.** `WC_SVR_FLAG_FUZZ` is reached only
  under `DEBUG_VECTOR_REGISTER_ACCESS_FUZZING` (`linuxkm_wc_port.h`); a certified
  build compiles `SAVE_VECTOR_REGISTERS2()` to
  `wc_save_vector_registers_x86(WC_SVR_FLAG_NONE)`.
* **The fallback is refused at compile time, not switched off at run time.**
  `fips.h` and `settings.h` `#error` on `WC_C_DYNAMIC_FALLBACK`; there is no
  mechanism to disable it at run time, so there is nothing that could be
  characterised as a disable toggle.
* **PAA versus software-only is a configure choice**, producing two binaries.
  That is two builds, which every software module with PAA already does.
* **Processor stepping is not a toggle.** It has no operator input, no API and no
  setting. It is a write-once read of what the processor reports, fixed for the
  life of the module on a given operating environment. Nobody can move it, so
  there is nothing to constrain and nothing to declare.

**Now trace the other path.** Keeping the fallback requires per-implementation
CASTs. Per-implementation CASTs require the ability to force each implementation
in order to test it — item 1, "the operational test has to be able to select a
lane deterministically and then confirm which lane actually executed." **That
mechanism is the run-time toggle**, and it is precisely the thing the laboratory
says may make the module hybrid.

| | Run-time toggle | Hybrid question | RFG |
|---|---|---|---|
| **Section 3.0: delete the fallback, keep stepping** | none exists | not raised — nothing to toggle | **not needed** |
| **Keep the fallback and make it compliant** | required, by item 1 | raised, and the laboratory leans toward hybrid | **required; 90 days, may be refused** |

**The proposal to keep the fallback is what creates the hybrid exposure and the
90-day schedule dependency.** Both disappear by deleting the fallback — which is
item 8, arrived at by the laboratory independently.

**The precedent answers the question without an RFG.** Module versions v5.2.1,
v5.2.4 and v6.0.0 all shipped CPUID-selected implementations and were validated
as *Software, Multi-Chip Stand Alone* — Cert #4718's own security policy says so
(section 3.4.1). That establishes that processor-capability selection did not
make this module hybrid. An RFG would be needed to introduce a toggle; none is
needed to keep doing what has been validated.

**Open item.** If the laboratory's concern extends to CPUID stepping itself, and
not only to an operator-facing toggle, then it reaches the three prior
certificates as well and the disagreement is much larger than this module.
Establish which of the two is meant before conceding anything — the answer
changes the scope from "v7's design" to "wolfSSL's validated product line."

### 3.2.2 Estimate of the work to keep the fallback

**Man-days**, assuming a competent engineer already familiar with this codebase,
a capable LLM assisting, and the RFG coming back favourable.

The LLM assumption compresses **authorship-bound** work — writing the reporting
API across every algorithm, wiring 70-90 CASTs, drafting the document set. It
does **not** compress **machine-bound or iteration-bound** work: build and boot
cycles, a QEMU cell that has to be re-run after a failure, ACVP vector
processing, laboratory review, or the RFG clock. Rows of the second kind are
estimated on their own terms.

| Workstream | Days |
|---|---|
| Per-implementation identity and reporting API, all accelerated algorithms | 4-6 |
| Deterministic lane control (run-time toggle), validated against processor capability | 3-4 |
| Per-implementation CASTs: 26 → ~70-90, vectors, wiring, error codes | 6-8 |
| State machine redesign: per-implementation CAST state, one-shot fallback, degraded latch † | 5-7 |
| Status/error rework so no substitution is reported as success | 2-3 |
| **Implementation subtotal** | **20-28 days** |
| Operational-test expansion: each lane x each injection x degraded-mode transitions | 4-6 |
| Operating-environment matrix expansion and debugging across the multiplied cell count ‡ § | 15-25 |
| CAVP/ACVP runs per implementation rather than per algorithm ‡ | 4-7 |
| PL-R34 / PL-R36 / state machine diagrams / algorithm and OE tables | 3-4 |
| **Test and validation subtotal** | **26-42 days** |
| **Total** | **46-70 man-days (~9-14 man-weeks, roughly 2-3 months)** |

† The state machine redesign is the highest-risk line in the table, not the
longest. It reworks the core of a validated module, and an error there is a
submission blocker rather than a bug.

‡ Machine-bound. Each cell is build, boot, operational test, harness, log-check,
and a re-run for every failure found. Nothing about that gets faster with better
authorship.

§ **This row is disputed and is the largest single line in the table.** It was
sized on the laboratory's item 5 (a cell per lane-and-fallback combination, 12
cells going to 40-60). wolfSSL's position is that lanes are not operating
environments and the ceiling is 2x, which would put this row nearer 4-8 days and
drop the total by roughly 10-20 man-days. **Do not quote the 46-70 total without
saying which reading of item 5 it assumes** — it currently assumes the
laboratory's.

Calendar risk sits on top and does not compress at all: **90 days per RFG
turnaround**, possibly more than one, with a real chance the answer forecloses
the design after the work is done. Item 6 is not an estimate at all — if it
holds, a hybrid embodiment is a different validation, not a longer one.

### 3.3 Why we delete the fallback rather than make it compliant

Two reasons, in order of weight.

**First, section 2.1.** Testing both implementations satisfies the Implementation
Guidance. It does not address the security property: the C AES is table-driven,
the accelerated one is constant-time, and the fallback lets an external party
choose between them mid-stream on the same key with no indicator. A CAST on each
does not make an attacker-influenceable downgrade acceptable — it just means
both implementations were tested before one of them got selected against the
operator's interest. That argument stands on its own and needs no Implementation
Guidance citation at all.

**Second, the compliant alternative is more work than removal, not less.** Today
the CAST machinery is **per algorithm**: 29 CAST identifiers in
`wolfssl/wolfcrypt/fips_test.h`, a single `fipsCastStatus[FIPS_CAST_COUNT]`
status array, and 542 gating sites in `fips.c`. **Not one CAST names an
implementation.** To make dual implementations compliant we would have to build,
and then keep validated:

1. **A CAST per (algorithm × implementation).** SHA-512 alone carries five
   implementations at once on x86_64 (section 12.6). AES has C, AES-NI, AVX1,
   AVX2, VAES_AVX2 and VAES_AVX512 lanes across five modes. The identifier space
   and the status array stop being per-algorithm.
2. **An implementation-aware state machine.** `fipsCastStatus[]`, every
   `AlgoAllowed()` gate and every `DEGRADE_STATE()` becomes per-implementation:
   if the C twin's CAST fails, the module must stop using *the C twin* while
   still permitting AES-NI. Degraded mode is currently per algorithm.
3. **A way to force each implementation, deterministically, in order to test
   it.** A CAST must pass before first operational use of *that implementation*
   (ISO/IEC 19790:2012 §7.10.3.2 `[10.27]`). Under run-time dispatch the C twin's
   first use is whenever a vector-register save happens to fail — possibly in
   softirq. So either every implementation's CAST runs at boot, which requires
   exactly the deterministic selection mechanism we are removing, or a CAST has
   to run at the moment of the first switch, in the context that made the switch
   necessary.
4. **A mechanism that reports which implementation served a request.** Be precise
   about where this obligation comes from, because it is easy to cite the wrong
   thing. It is **not** IG 2.4.C: that indicator is about whether a *service*
   used an approved algorithm in an approved manner, and it explicitly does not
   require API-level granularity — "it is not required to provide the indicator
   at the API level of cryptographic functions, as long as the service
   implementing the API provides the corresponding indicator." Nothing in 2.4.C
   asks the Cryptographic Officer to learn which lane ran.

   It is required for a plainer reason, and the laboratory said so directly
   (section 3.2 item 1): **you cannot self-test an implementation separately
   unless you can tell which implementation ran.** GeneralNote1's obligation is
   untestable without it. It is therefore a prerequisite of conformance, not an
   indicator requirement — and it is new public API surface on every affected
   algorithm. Section 12.5 shows the operational cost of not having it.
5. **Per-implementation operational-test evidence.** Each implementation needs
   its own injection path and its own TE coverage, multiplying the evidence set
   the laboratory reviews.
6. **Both PAA and non-PAA rows tested and claimed per operating environment**,
   per IG 2.3.C above — which is ACVP and OE-table cost on top of the module
   work.

Against that, the enforcement mechanism for the elected posture is a pair of
`#error` directives in `settings.h` and `fips.h`.

**Do not read that as "the change was small."** Measured against the
with-fallback branch, removing the fallback is **81 files changed, +15,021 /
-1,801**. The prohibition itself is cheap; making every algorithm actually
propagate a save failure instead of substituting a lane was not.

**IG 2.3.C's two testing routes, because the operating-environment arithmetic
depends on which one applies:**

> Option 1: "Perform module testing with and without PAA/PAI for all OEs on the
> certificate. a. OEs would either be listed with and without on the certificate
> (which is typical)…"
>
> Option 2: the "similar OE" economy, requirement 2c — "There shall be no
> differences in module binaries executed on any of the OEs that are considered
> 'similar', whether testing with or without the PAA/PAI."
>
> — FIPS 140-3 IG 2.3.C, Testing requirements

The two-binary structure is **not** created by anything in this posture. Under
section 3.0 there are two builds — PAA-configured and software-only — exactly as
in v5.2.1, because there is no run-time switch that turns PAA off inside one
binary. Cert #4718 lists platforms with and without PAA, which is Option 1's
"typical" shape, and Option 1 carries **no binary-identity clause**. So the
factor of two on PAA-capable platforms is the pre-existing baseline for this
product line, not a penalty this posture introduces.

**Open item — confirm before quoting any of this to the laboratory.** Cert
#4718's policy says a platform was "tested both with and without PAA **unless an
identical or similar platform had already been tested**", which layers Option 2's
economy on top of Option 1. Exactly which route applied to which row, and
whether the "similar" economy was ever claimed *between* a PAA build and a
software-only build (it cannot be — different binaries), is **not** determined
here. It needs the #4718 test report. Related and also unchecked: whether the
12-cell operating-environment matrix already runs both postures per cell
(`matrix/docs/MATRIX-MASTER-RESUME.md`).

**The honest comparison:**

| | Removing the fallback | Making the fallback compliant |
|---|---|---|
| Engineering | done — 81 files, +15,021/-1,801 against the with-fallback branch | **46-70 man-days = 9-14 engineer-weeks**, on the laboratory's reading of item 5 |
| Schedule dependency | none — no toggle, so no RFG | **90 days per RFG turnaround**, possibly repeated, possibly refused |
| Module embodiment | unchanged (Software, Multi-chip Standalone), as validated | **Hybrid Module risk** — created by the lane-selection toggle the design requires; unresolved |
| CAST set | 26, one per algorithm — correct under the *reachable* reading, which is what section 3.0 elects and what v5.2.1 / v5.2.4 / v6.0.0 shipped | ~70-90 only under the strict *contained* reading — unsettled |
| Operating-environment matrix | **2x on PAA-capable OEs** — the pre-existing baseline, not a penalty of either choice | **2x, not 5-6x** — wolfSSL dissents from item 5; lanes are not operating environments |

**Removing the fallback is the smaller change by a wide margin, it is done, and
it is the one that also fixes section 2.1.**

Sections 2.1 and 12.5 — the load-bearing security arguments — are discharged by
removing the fallback alone, because that is what takes the reachable-lane count
on one operating environment from 2 back to 1. The *contained* count is
unchanged by that removal and remains 5-7 for SHA-512; it matters only if the
laboratory reads the CAST obligation as attaching to contained implementations.
**Section 3.0 takes that decision: the fallback goes and the stepping stays.**

### 3.4 What this means for the submission

State it as an election, not a mandate, and state it in terms of what is
*reachable*, which is the property the CAST set actually covers:

> The module is built in one of two configurations: with PAA, or software-only.
> In a PAA configuration each algorithm selects its implementation **once, from
> processor capability, at first use**, and that selection is never revised for
> the life of the module. Exactly one implementation of each algorithm is
> therefore reachable on any given operating environment, which is what the one
> CAST per algorithm covers. **No run-time condition substitutes a different
> implementation.** In particular, a vector-register save failure returns an
> error to the caller; it is never answered by executing a different
> implementation and reporting success. This is the same construct validated in
> module versions v5.2.1, v5.2.4 and v6.0.0. What v7 removes is the kernel
> fallback that could substitute an implementation at run time.

That keeps section 2.1 as the load-bearing argument, which is the one that does
not depend on anybody's reading of the Implementation Guidance. And it does not
overclaim: we are not telling the laboratory that dual implementations are
forbidden, which is a position the laboratory would correct — we are telling
them what this module does and why the election makes it conformant.

### 3.4.1 What changed since Cert #4718

**Earlier wolfSSL certificates shipped the dual-implementation construct.**
Verified against the certificate security policy and the frozen module tree.

**Cert #4718 (module v5.2.1), `140sp4718.pdf`:**

* The same platform is listed twice, `PAA/PAI = Yes` and `= No`: Intel Ultrabook
  2-in-1 / Core i5-5300U, EndaceProbe 2144, EndaceProbe 2184, and Anyware
  Trusted Zero Client / AMD Ryzen Embedded R1305G (Table 6).
* "The Module conforms to [140-3 IG] 2.3.C ... The Intel Processor AES-NI
  functions are identified by [140-3 IG] 2.3.C as a known PAA."
* Embodiment: "Multi-Chip Stand Alone" — Software, not Hybrid.
* Route taken: "that platform was tested both with and without PAA **unless an
  identical or similar platform had already been tested**." That is IG 2.3.C
  Testing requirements **Option 2**, the "similar OE" route.

**`XXX-fips-test-v5.2.1` (FIPS module v5.2.1, library 5.9.1), read directly:**

* `wolfcrypt/src/aes.c:713` — `#elif defined(WOLFSSL_AESNI)`, whose arm reaches
  `#define NEED_AES_TABLES` at `:720`. The C tables are compiled *because* AES-NI
  is on.
* `aes.c:3903-3904` — `#ifdef WOLFSSL_AESNI` then `if (aes->use_aesni)` with a
  live software `else`, inside `wc_AesEncrypt`.
* `aes.c:6197` — `haveAESNI = Check_CPU_support_AES()`, run-time CPUID, latched
  in `checkAESNI`.
* `sha512.c:1413-1473` — a five-way `Transform_Sha512_p` dispatch over
  `AVX2_RORX`, `AVX2`, `AVX1_RORX`, `AVX1` and `_Transform_Sha512`, selected from
  `cpuid_get_flags()`. `sha256.c:488-540` is the same shape.

**Two arguments about that must not be offered to a laboratory.**

**Not "the second implementation was optimized out."** `haveAESNI` is a run-time
value, so neither arm of `aes.c:3904` can be folded and both are in the shipped
object. The certificate forecloses the argument by itself: the `PAA/PAI = No`
rows in Table 6 would have had nothing to execute, and IG 2.3.C Option 2c
*requires* the binary to be identical with and without PAA. This is checkable in
minutes and it does not survive.

**Not "nothing changed in the rules."** True for AES, unsupportable for SHA-512.

**The position, stated as two categories.**

*Category A — PAA offload.* IG 2.3.C, Testing requirements 2c, is explicit:
"(note: the PAA/PAI code is considered outside of the logical boundary of the
module)". On that reading an AES-NI build and a C build are not two
implementations *inside* the boundary; they are one in-boundary implementation
with an optional out-of-boundary offload, and the paired `Yes`/`No` operating
environment rows are the 2.3.C testing route built for exactly that construct.
**This document asserts no finding against Cert #4718's AES-NI construct.** The
CMVP names Intel and AMD AES-NI as known PAA; SHA-NI is the same kind of thing.

*Category B — a second software implementation.* AVX1, AVX2, RORX (a BMI2
rotate), AVX512, and the SP / ML-KEM / ML-DSA vector lanes are general-purpose
instruction set, not cryptographic accelerators, and the CMVP does not name them
as PAA. A build carrying them carries **several software implementations of one
algorithm inside the boundary**, selected at run time. The category A argument
does not reach them. SHA-512 is the clean case: there is no SHA-512 PAA on x86,
so all five `sha512.c` transforms are category B and no PAA/PAI defence applies
to any of them.

And category B has a named Implementation Guidance example against it — **IG
10.3.B, Additional Comments 1**, quoted in section 3.1.

**So the accurate account is neither of the two easy ones.** Not "nothing
changed": the category B multiplicity is real, it shipped, and IG 10.3.B names
the case. Not "the earlier module was wrong": no prior validation put the
question, the category A construct is defensible on the Implementation
Guidance's own boundary sentence, and we do not challenge it. What we say is
that the question was never put, and wolfSSL is answering it in v7 on its own
initiative rather than in response to a finding.

**Open item.** The category A / category B split is this document's reading of IG
2.3.C's boundary sentence, and it has **not** been put to Aegisolve. If the
laboratory treats an AVX2 lane as an in-boundary second implementation — which
the plain text of 10.3.B supports — then category A shrinks to AES-NI and SHA-NI
only, and nothing above changes. If the laboratory instead reads category A more
broadly, the elected posture is stricter than it needs to be for AES. Put it to
them before relying on the split in a submission.

**Certificate status.** Of the three module versions cited as precedent, only
**v5.2.1 is a granted certificate (#4718)**. v5.2.4 and v6.0.0 are still in
process at the CMVP and have no certificate numbers to cite. The precedent does
not depend on the grant: what it rests on is that those three modules were
*built and submitted* with one implementation per algorithm and no run-time
fallback, which is a property of the submitted code. v5.2.1 being granted on
that basis is the strongest single data point; v5.2.4 and v6.0.0 show the
posture is continuing practice rather than a one-off.

---

## 4. Site index

| Marker sites | Section |
|---|---|
| `linuxkm/x86_vector_register_glue.c`, `linuxkm/lkcapi_sha_glue.c` | 2, 5, 13.3, 13.4 |
| `wolfssl/wolfcrypt/rng_bank.h`, `wolfcrypt/src/rng_bank.c` (the DRBG bank) | 5.2 (what it is), 11 (whether it belongs) |
| `wolfcrypt/src/sha256.c`, `sha512.c` (mid-hash switching) | 6 |
| `wolfcrypt/src/sha256.c`, `sha512.c` (`"not reachable"` branches) | 7 |
| `wolfcrypt/src/wc_frodokem_mat.c` | 8 |
| `linuxkm/lkcapi_aes_glue.c`, `wolfcrypt/src/aes.c`, `wolfssl/wolfcrypt/aes.h` | **2.1** (the side-channel downgrade), 9, 13.5.10 |
| `wolfcrypt/src/wc_mldsa.c`, `wc_mlkem_poly.c`, `wc_slhdsa.c`, `sha3.c`, `sp_x86_64.c`, `ge_operations.c` | 10, 13.5 |
| `configure.ac`, `settings.h`, `wc_mldsa.h`, `wc_mlkem.h`, `sha3.h`, `memory.h`, `memory.c`, `lkcapi_glue.c`, `scripts/fips-no-svr-fallback-check.sh` | 1, 3 (posture plumbing and the gate) |

Sections 5 to 11 each use the same shape: **original problem / original solution
/ how it caused flakiness or a compliance issue / correct fix** — the last
showing the original problem actually handled, not traded away.

---

## 5. The DRBG in softirq

**Original problem.** The failure in section 2: the DRBG was called from timer
softirq, refused the vector registers, could not complete its SHA-256, and put
the module into `FIPS_MODE_FAILED`.

**Original solution.** A C twin selected on refusal (`WC_C_DYNAMIC_FALLBACK`),
plus `WC_RNG_BANK_FLAG_NO_VECTOR_OPS` making the DRBG preemptively inhibit
vector operations so the twin was used there by design.

**How it caused a compliance issue.** Two implementations of one approved
algorithm selected at run time — section 3. Both halves.

**Traces to section 1.** The insertion point required output where the operating
environment provides no facility for it; the fallback was the override.

**Correct fix.** Move the "slot free" marker to its own `in_use` field so pid 0
is representable, delete the `pid == 0` condition, and apply the operating
environment's actual rule. The inhibit flag is deleted, its bit retired and not
reused.

**How this solves the original problem.** Softirq gets the vector registers, the
SHA-256 completes, and the module stays in `FIPS_MODE_NORMAL`. Measured in
section 12.

### 5.1 `get_random_bytes()` is a different subsystem

`get_random_bytes()` lives in `drivers/char/random.c`, which contains **no
crypto API calls at all** — no `crypto_alloc_*`, no `stdrng` — and uses ChaCha20
and BLAKE2s directly. `stdrng` is reached only via
`crypto/rng.c:crypto_get_default_rng()`, whose callers are `crypto/dh.c`,
`crypto/ecc.c`, `crypto/geniv.c`, `net/tipc/crypto.c` and two hardware drivers.
Registering as `stdrng` never put the module in the boot-randomness path.
Registration is also gated on `LINUXKM_LKCAPI_REGISTER_HASH_DRBG_DEFAULT`, which
no validated kernel build enables.

### 5.2 The DRBG bank holds generators, not bytes

This is stated explicitly because "pre-generated output" or "the pre-filled
bank" would describe a stored pool of random bytes handed out later, which would
be a serious problem in a validated module. That is not what the code does.

```c
/* wolfssl/wolfcrypt/rng_bank.h:68 */
struct wc_rng_bank_inst {
    wolfSSL_Atomic_Int lock;
    WC_RNG rng;
};
```

That is the whole instance: a lock and a generator. (Without atomics the lock is
a plain `int`.) `struct wc_rng_bank` holds a refcount, heap pointer, flags, three
affinity callbacks, a callback argument, a count, and **an array of those
instances** — typically one per CPU.

> **The bank holds DRBG instances. It does not hold generated bytes.** There is
> **no output buffer, no cache of output, no pool, no prefill and no refill
> path** anywhere in the struct or the file. Nothing is generated in advance and
> stored.

Each instance is a full `WC_RNG`, seeded at instantiation, producing output only
when a caller asks. Several instances exist to avoid CPUs contending on one
lock.

Two things that otherwise get misread: "cache" appears once
(`wolfcrypt/src/rng_bank.c:386`) and refers to caching *DRBG seeding* at
startup, not output; and the sole `wc_RNG_GenerateBlock()` in that file (line
986) generates four bytes into a local scratch and **discards them**, solely to
force a reseed.

This subsection says what the structure contains. It does not claim the bank is
proven, sound, or the right answer to anything — section 11 is where that is
decided.

### 5.3 Why not just register earlier in boot

Because approved services cannot precede the pre-operational self-tests. All
ISO/IEC 19790:2012:

- **§7.10.1 `[10.03]`** — pre-operational self-tests "shall be performed and
  passed successfully prior to the module providing any data output via the data
  output interface."
- **§7.10.2.1 `[10.15]`** — they shall pass before the module transitions to the
  operational state.
- **§7.2.4.2 `[04.31]`**, addressing loaded code by name — the module "shall
  withhold execution of any loaded or modified approved security functions until
  after the pre-operational self-tests specified in 7.10.2 have been successfully
  executed."
- **§7.10.3.2 `[10.27]`** — the algorithm self-test shall be performed prior to
  first operational use of that algorithm.

So registering earlier extends coverage backwards by **zero**: before the
self-tests pass there is no operational module, and anything it emitted would be
output the standard forbids. It only adds risk — less entropy gathered, fewer
kernel services up, more of boot depending on unproven code.

Consequence for customers, stated once: coverage runs from self-test completion
to unload, over the module's certificated services on the listed operating
environment, including anything a product does *by calling the module*.
Kernel-internal randomness before the module loads is outside the boundary —
true of every software module, since the operating system runs before anything
in it can load.

---

## 6. `sha256.c` / `sha512.c` — mid-hash implementation switching

**Original problem.** A hash spans many calls. If the vector registers became
unavailable mid-hash, the operation would have to fail and the caller restart.

**Original solution.** Re-decide per call: `sha_method` records processor
capability only, and actual use is re-tested at each transform. To let the two
back ends interoperate mid-stream, the buffer is kept big-endian at all times
with just-in-time byte swapping around the C leg
(`WC_NO_INTERNAL_FUNCTION_POINTERS`, `WC_SHA512_RAW_BE_BUFFER`).

**How it caused a compliance issue.** One digest can be produced partly by each
implementation, with the split falling wherever unrelated system activity puts
it. Section 3 applies — and separate CASTs would still not cover it, because no
single implementation produced the result. The module also cannot report which
legs ran.

**Traces to section 1.** It makes an operation survive a refusal the operating
environment issues deliberately, by swapping implementations under the caller.
The byte-swap shims exist only so the two can hand off: a cost of carrying both,
not a reason to.

**Correct fix.** One implementation executes per operating environment, chosen
from CPUID at first use and never revised; `settings.h` `#error`s the swapping
mechanism in a certified build.

**How this solves the original problem.** The case that mattered no longer occurs
— it was the `pid == 0` condition of section 2. Where the vector registers
genuinely cannot be had, the call returns an error the caller can check, log and
retry from a permitted context. A digest silently produced by an untested leg
offers none of that.

---

## 7. `sha256.c` / `sha512.c` — the `"not reachable"` branches

**Original problem.** A switch over `enum sha_methods` needs an arm for the C
value, or the compiler warns.

**Original solution.** Keep the arm and annotate it *"not reachable — the C path
exits above, before vector register save."*

**How it caused a compliance issue.** The stated reason does not hold where it
was written, so the arm is live code calling a second implementation:

- `sha256.c:inline_XTRANSFORM()` — the early exit tests `sha_method ==
  SHA256_C` only. `SHA256_UNSET` and any other value reach the arm. The
  `sha512.c` twin is the same shape.
- `sha512.c:Transform_Sha512_Len()` — in the non-fallback build there is **no
  early exit above at all**. The annotation cites a path not present in that
  function.
- Same function, without `WC_SHA512_RAW_BE_BUFFER`: the arm sets `ret = 0` and
  hashes nothing.

A live arm calling a second implementation *is* a second implementation, so
section 3 applies. Independently: an unreachability claim a validated module
rests on must be demonstrated, not asserted in a comment.

**Correct fix.** Make it structurally impossible: with no fallback compiled, the
arm calls what every other arm calls, and a save failure returns an error.

**How this solves the original problem.** The switch is still complete, so the
warning stays silenced; correctness no longer rests on a whole-program argument
a later edit can invalidate.

---

## 8. `wc_frodokem_mat.c` — the re-key

**Original problem.** The AES-NI / VAES row kernels consume `aes->key` directly,
which holds a valid AES-NI-layout schedule only if `wc_AesSetKeyDirect()` ran
with the vector registers. Under the fallback a failed save inside SetKey
**returned success having keyed only `aes->key_C_fallback`**, so the kernels
would read a schedule never written.

**Original solution.** Detect it and re-key inside the held region, justified by
*"the nested `SAVE_VECTOR_REGISTERS2()` always succeeds"*. The return value was
not checked.

**How it caused flakiness and a compliance issue.** It repairs damage the
fallback caused — a SetKey reporting success with its output unset is the defect.
And the justification is false: in `wc_save_vector_registers_x86()` the
non-outermost path returns `WC_ACCEL_INHIBIT_E` when the enclosing region was
entered inhibited, `BAD_STATE_E` on recursion-counter overflow, and
`BAD_STATE_E` for `WC_SVR_FLAG_MAYBE_INHIBIT` at non-outermost depth. With the
return discarded, a failure leaves the schedule unset and the kernels read it
anyway — wrong answer, not error. The construct also maintains two key schedules
for one algorithm.

**Traces to section 1.** A self-inflicted problem addressed with more of the
mechanism that caused it, resting on an assumption about the operating
environment that the operating environment does not honour.

**Correct fix.** Remove the fallback: SetKey either keys the one schedule and
succeeds, or returns an error.

**How this solves the original problem.** The kernels always read a schedule that
was actually written, because there is one schedule and one way to succeed. The
re-key and the claim about nested saves both become unnecessary.

---

## 9. `lkcapi_aes_glue.c` — "there's no AES-XTS in Cert 4718"

**Original problem.** The AES-XTS shim had to decide whether the fallback
applied.

**Original solution.** Use it unconditionally, on the ground that AES-XTS is
absent from Cert 4718's algorithm list.

**How it caused a compliance issue.** The scope of a validation is the module
being validated; Cert 4718 is a different module. v7.0.0 wraps AES-XTS as an
approved service — `wc_AesXtsEncrypt_fips()`, `wc_AesXtsDecrypt_fips()`,
`wc_AesXtsEncryptSector_fips()` and siblings in `fips.c` — so section 3 applies
to AES-XTS here. A rule about what a module may contain does not switch off per
algorithm by consulting another certificate.

**Correct fix.** One rule for the whole module, no per-algorithm exemptions;
`settings.h` and `fips.h` both refuse it.

**How this solves the original problem.** The shim has no decision left to make.

---

## 10. `wc_mldsa.c` / `wc_mlkem_poly.c` — what carrying two implementations cost

**Original problem.** Because dispatch could change between calls, NTT-domain
data at rest could be written by one implementation and read by the other. Any
representation difference becomes a wrong answer.

**Original solution.** Force every representation dispatch-invariant, and
re-initialise shared state the other leg might have touched. In ML-DSA the
non-full AVX2 NTT/invNTT keep coefficients in permuted (lane-interleaved) order
that only their own consumers understand, so they were disabled in favour of
standard-order variants — **~2% on NTT, ~4% on invNTT**. In ML-KEM,
`mlkem_derive_secret()`'s buffer-stuffing shortcut is valid only on a freshly
initialised sponge; the re-init was applied only under `WC_C_DYNAMIC_FALLBACK`,
on the argument that the C legs were otherwise unreachable. They are not — they
are the unconditional `else` of the dispatch ladder — so the correctness of a
shared secret rested on a whole-program reachability argument, to save one SHAKE
init per decapsulation.

**How it caused flakiness.** None of this defends against a hardware fault. Each
defends against *the module's own dispatch changing mid-operation*. Where a
defence is present, we pay in speed; where one is missing, the result is a
**silently wrong answer** no CAST detects, because the output is well-formed.
Four such defects were found by reading (`stress/README.md`):

| Defect | Effect if shipped |
|---|---|
| `mlkem_cmp()` returns a constant-time 0/-1 mask, propagated as an error code | silently wrong shared secret |
| Hint generation returns `-1` in-band while callers test `-1` as an error | signature built from a hint list never written |
| Accelerated arm wrote permuted order; fallback wrote standard order | silently wrong signature after a failed save |
| Sponge context reused across a derivation | wrong derived secret |

**Traces to section 1.** Every one of these is a tax paid to keep a second
implementation the operating environment never asked us to carry.

**Correct fix.** Let CPUID alone decide, once, so invariance follows from the
write-once latch rather than from a reachability argument; and take the cheap
unconditional correctness step where one exists — the ML-KEM sponge is now
initialised unconditionally, as the non-`USE_INTEL_SPEEDUP` path always did.

**How this solves the original problem, and what it returns.** Data written by an
operation is read by the same implementation, always. The permuted-order
variants are safe again, so ML-DSA recovers the 2% / 4%; the SHA byte-swap shims
are unnecessary; and the defect class above cannot recur, because its
precondition is gone.

**Measured in kernel space:** **+4.6% sign, +4.8% keygen, +3.8% verify** at
ML-DSA-44, against a within-arm noise floor of ~1%.

**Do not generalise that to the whole module.** The recovery holds only when the
lane that runs is the one the part best supports. Measured against a build whose
lane was fixed at configure time below the operating environment's CPUID
capability, the x86_64 kernel build was **43-78% slower on AES-GCM / CTR / XTS /
GMAC and 48-85% slower on everything driven by SHA-256**. Running the lanes the
part actually has removes the entire deficit while still running one
implementation per algorithm — which is what CPUID selection at first use does.
Section 12.1 has the numbers and the control that isolates the cause.

---

## 11. `rng_bank.c` / `rng_bank.h` — the per-core DRBG bank

**Decision: compiled out of certifiable FIPS flavours; kept for the uncertified
`fips=dev` flavours.** This is not a claim that the mechanism does not work — it
does, and section 11.2 gives the number. It is a removal of unjustified
complexity from the validated boundary.

**Original problem.** Stated once, in the whole of the origin commit message
(`29cf3eb84e`, 2025-06-05, PR #8840): *"linuxkm/lkcapi_sha_glue.c: refactor DRBG
wrapper to instantiate one DRBG per core, to relieve contention."* The pull
request contains **no benchmark, no profile, no bug report and no number**. It
was generalised into `rng_bank.c` / `rng_bank.h` seven months later
(`3c15be661`, 2026-01-06) with a changelog of what was added and no rationale for
why.

Note what it is *not*: a softirq workaround. The chronology refutes that. The
per-core design landed 2025-06-05; the `task_pid_nr(current) == 0` refusal that
actually caused the hang landed 25 days later (`b3944a73c`, 2025-06-30).

**Original solution.** One DRBG instance per core, plus a checkout/checkin
protocol, affinity callbacks, failover between instances, per-instance reinit,
and `struct wc_rng_bank` in a public header.

### 11.1 The correctness need is gone

The per-instance compare-and-swap makes a single shared `WC_RNG` correct across
threads. Measured with a working negative control — exclusion removed: **26,490
duplicate blocks**; with the compare-and-swap: **0 duplicates**, at 2/8/16/24/48
threads over 960,000 blocks. A negative control that produces duplicates is what
makes the zero meaningful.

### 11.2 The throughput need is not present in this workload

On a synthetic draw loop the bank is genuinely faster — **328 MB/s shared versus
5.8 GB/s banked, 12-15x**. The mechanism works.

On what the kernel's `stdrng` actually serves, it does not matter. ECDSA sign at
full core saturation (24 threads on 24 cores): shared **80,833/s**, bank
**80,962/s** — **0.16% apart**. ECC keygen likewise. Asymmetric operations are
compute-bound; the draw is noise beside them.

### 11.3 The cost, which is not small

With the SP 800-90B MemUse conditioner, instantiation is **14.5 ms per instance,
perfectly linear**:

| Configuration | Instantiation | Raw entropy |
|---|---|---|
| 1 DRBG | 21.4 ms | 132 B |
| 24-CPU host (28 instances) | **409 ms — 19x** | 3,696 B — **28x** |
| 128-CPU host | **1.92 s — 90x** | proportionally |

And because `cra_ctxsize = sizeof(struct wc_rng_bank)`
(`linuxkm/lkcapi_sha_glue.c`), that is paid **per `crypto_alloc_rng("stdrng")`
transform, not once per module**. Every consumer that allocates a transform pays
it again.

Add eight defect fixes (+319 lines) and an ABI-visible struct in a public
header, and the complexity is carried by the validated boundary in exchange for
0.16%.

**Dead in most builds anyway.** Of 19 `libwolfssl.ko` on disk, `rng_bank.o`
links into all 19; only **5 have any caller**. **14 carry it for nothing.**

### 11.4 Upstream ships the design the bank replaces

This is the point that settles it. Linux's own `crypto/drbg.c` serialises
**every** generate behind one `mutex_lock(&drbg->drbg_mutex)`
(`drbg_generate_long`, line 1512), and `crypto/rng.c` keeps **one** shared
`crypto_default_rng` systemwide — for the same consumers the bank is meant to
serve (`crypto/ecc.c`, `crypto/dh.c`, `crypto/geniv.c`, `net/tipc/crypto.c`).

Upstream ships exactly the design the bank exists to replace, and does it with a
*sleeping* lock — strictly more serialising than our compare-and-swap. We
support the operating environment; we do not redesign it. Here that principle
has a number attached: 0.16%.

### 11.5 Failure recovery by switching instances — not adjudicated

`wc_linuxkm_drbg_generate()` (`linuxkm/lkcapi_sha_glue.c`) responds to
`RNG_FAILURE_E` by calling `wc_rng_bank_inst_reinit()` and retrying. If reinit
fails, the instance's status is set to `WC_DRBG_FAILED` (`rng_bank.c:1071`) and
`wc_rng_bank_checkout()` thereafter diverts to other instances
(`rng_bank.c:633`).

The requirement in tension, ISO/IEC 19790:2012 §7.10.1:

> "If a cryptographic module fails a self-test, the module shall **[10.07]** enter
> an error state ... The cryptographic module shall not **[10.10]** utilise any
> functionality that relies upon a function or algorithm that failed a self-test
> until the relevant self-test has been repeated and successfully passed."

Recovering from a DRBG failure by re-instantiating and then routing to a sibling
instance is hard to square with `[10.10]`.

**Be precise about what is and is not established here.** The DRBG continuous
test path is intact: `DRBG_CONT_FIPS_E` (-209) is intercepted in `fips.c` and
drives `fipsMode = FIPS_MODE_FAILED` per SP 800-90Ar1 §11.3. The retry above is
keyed on `RNG_FAILURE_E`, a broader wolfCrypt error covering reseed and generate
failures, raised from a dozen sites in `random.c`. **Whether any self-test
failure actually reaches this retry, rather than being intercepted by `fips.c`
first, has not been determined, and the question has not been formally
adjudicated with the laboratory.** Do not repeat this as a confirmed violation.

What is worth stating plainly is the shape. This is the same pattern as the
algorithm fallback: a failure met by silently switching to another instance of
the thing that just failed. That is the pattern section 1 exists to rule out, and
it is a reason to keep the mechanism out of the validated boundary rather than
adjudicate it.

### 11.6 The exception, stated rather than buried

At **2x thread oversubscription** the shared RNG loses **28% on ECDSA sign**. The
mechanism is understood: a preempted compare-and-swap holder makes the others
spin. This is a real regression in that configuration and it is the strongest
argument the bank has.

Two things are not yet known, and neither is asserted here. In-kernel checkout
holders run under `local_bh_disable()` and `SAVE_VECTOR_REGISTERS`, so they are
**not preemptible**, which may remove the effect entirely. That is being tested
in-kernel separately. **The test is pending; the outcome is not predicted.**

**Correct fix.** Compile the bank out of certifiable FIPS flavours; keep it for
`fips=dev`, where the 12-15x synthetic gain is available to anyone who wants it
and no validation depends on it. The certifiable module uses one shared
`WC_RNG`, whose cross-thread correctness is measured in section 11.1.

**How this solves the original problem.** The original problem was contention,
and it is solved twice over. The compare-and-swap already provides the exclusion
the per-core design was built around, at 0.16% of the throughput on the workload
that matters — the same trade upstream makes with a heavier lock. What is removed
is 319 lines of fixes, an ABI-visible struct, up to 1.92 s of per-transform
instantiation, 28x the raw entropy draw, and a failure-recovery path (section
11.5) that would otherwise need adjudicating. If section 11.6's in-kernel test
shows oversubscription still hurts, that is a `fips=dev` tuning question, not a
validated-boundary one.

---

## 12. Evidence

### 12.0 The failure and its cause

| Measurement | Result |
|---|---|
| With `task_pid_nr(current) == 0` present | spins in softirq, `FIPS_MODE_FAILED`; **62,915 errors / 29.7 s**; **28.9 s clocksource stall**; no recovery |
| That line removed | timer softirq **0/2 → 2/2**; stays `FIPS_MODE_NORMAL` |
| Verification kernel | `CONFIG_PROVE_LOCKING` + `CONFIG_DEBUG_ATOMIC_SLEEP`; tree at `linux-kernel-versions/linux-6.6.99-lockdep`, both confirmed in `.config` |
| Line reinstated, nothing else changed | reproduced; **61,458 errors** |

### 12.1 Kernel-space performance: fallback versus one implementation

Raw console logs, per-algorithm CSV and the cell verdict are filed under
`matrix/evidence/kernel-PAA-fallback-vs-1algo-20260808T162944Z/64-bit-x86_64-intel-kernel-PAA-fallback-vs-1algo-benchmark/`.
Cell script:
`matrix/scripts/combos/64-bit-x86_64-intel-kernel-PAA-fallback-vs-1algo-benchmark.sh`.

**What was compared.** `wolfcrypt/benchmark/benchmark.c` autorun in kernel space
(`--enable-linuxkm-benchmarks`), linux-6.6.99 under `qemu-system-x86_64
-enable-kvm -cpu host` on an Intel Core Ultra 9 285K, 5 repeats per arm,
**interleaved** A,B,A,B,… so host-load drift lands on both arms rather than
biasing one.

| Arm | Source | Dispatch |
|---|---|---|
| **A** | `e395483fd` — the last commit *before* the fallback-removal work | `WC_C_DYNAMIC_FALLBACK` on; two implementations of AES/SHA-2/SHA-3, chosen from CPUID at run time |
| **B** | `24cf12184` + the live working tree | fallback forbidden; one implementation per algorithm, the lane fixed at **configure time** by the then-current `configure.ac` auto-selection |
| **B2** | source byte-identical to B; only the lane tokens differ (`VAES_AVX2`, `AVX1_SHA`, SLH-DSA `AVX2`) | one implementation per algorithm, lanes matching this part's CPUID |

Arm A is **not** the tip of `PQ-FS-2026-Part3-SecurityReview-with-fallback`. That
branch and the fix branch share a merge base but are 167 upstream commits apart,
and several of those commits touch the algorithms being measured (AES-GCM on
Arm, three ML-DSA/SLH-DSA shift fixes, an `aes.h`/`cpuid.h` split).
Tip-against-tip would have charged all of that to the fallback removal.
`e395483fd` is that branch's content on the *same* upstream base, so A→B is
exactly the fallback-removal change plus the configure-time lane selection arm B
used.

**Artifact proof, before any timing was trusted** (both directions, on the built
`.ko`, not on an `#ifdef`):

| Check | A | B |
|---|---|---|
| PAA instructions (`aesenc*`/`aesdec*`/`pclmul`/`sha256rnds2`) | 1710 / 321 / 224 | 1710 / 321 / 224 |
| Duplicate-implementation symbols (`Transform_Sha256`, `_Transform_Sha512`, `BlockSha3`, `Sha256_SetTransform`, `Sha512_SetTransform`, `AesEncrypt_C`, `AesDecrypt_C`, `AES_GCM_encrypt_C`, `AES_GCM_decrypt_C`, `AesXtsEncrypt_sw`, `AesXtsDecrypt_sw`) | **11 of 11 present** | **0 present** |
| Text symbols | 5,561 | 5,188 |

`Sha256_SetTransform` / `Sha512_SetTransform` are the run-time implementation
*selectors*: their presence in A and absence in B is the fallback itself, not a
side effect of it. Both arms passed the power-on self-test with their own
grafted in-core hash, so each run demonstrably loaded its own module — a swapped
`.ko` fails `-203` and never reaches the benchmark.

**Noise floor:** within-arm relative standard deviation, median **1.00%**, p90
**2.64%** over 356 arm-algorithm pairs. Anything below ~2.6% is reported as
indistinguishable.

#### 12.1.1 The result

Removing the fallback is **free**. Running the wrong lane is not.

**Which arm is the shipping design: B2.** The elected posture selects the lane
from CPUID at first use, so it lands on the lanes the part actually supports —
arm B2, which is within noise of the fallback build. Arm B's deficit came from a
configure-time lane choice that no longer exists in this tree, and is reported
here because it is what was measured, not because it describes what ships.

| Family | A (fallback) | B (configure-fixed lane) | **B2 (CPUID-matched lanes)** |
|---|---:|---:|---:|
| AES-128-GCM-enc | 19,106 MiB/s | 10,386 **-45.6%** | 19,293 **+1.0%** (noise) |
| AES-256-GCM-dec | 18,743 | 9,236 **-50.7%** | 18,839 **+1.0%** (noise) |
| AES-256-CTR | 21,360 | 9,459 **-55.7%** | 21,679 **+0.9%** |
| AES-XTS-enc | 26,586 | 12,216 **-54.0%** | 26,837 **+0.9%** |
| AES-XTS-dec | 26,401 | 12,124 **-54.1%** | 26,758 **+0.8%** (noise) |
| GMAC Table 4-bit | 14,816 | 3,191 **-78.5%** | 15,011 **+1.2%** |
| HMAC-SHA256 | 5,028 | 766 **-84.8%** | 5,066 **+0.8%** † |
| PBKDF2 | 263 KiB/s | 83 **-68.6%** | 262 **-1.0%** (noise) |
| RNG SHA-256 DRBG | 556 MiB/s | 290 **-47.9%** | 562 **+2.5%** |
| SLH-DSA-SHAKE-F 128 sign | 132 ops/s | 57 **-56.9%** | 134 **+1.9%** |
| SLH-DSA-SHAKE-S 256 sign | 4.4 | 1.8 **-57.7%** | — |
| SLH-DSA-SHA2-F 128 sign | 100.5 | 65.0 **-35.3%** | 100.5 **0.0%** (noise) |
| ML-DSA-44 sign | 25,743 | 26,933 **+4.6%** | 27,677 **+6.6%** |
| ML-DSA-65 sign | 16,486 | 17,277 **+4.8%** | — |
| ML-KEM-768 decap | 66,695 | 66,697 **+0.0%** (noise) | — |
| SHA-512 | 1,254 | 1,248 **-0.5%** (noise) | — |
| SHA3-256 / SHA3-512 | 906 / 481 | **-0.3% / +0.3%** (noise) | — |
| AES-CBC-enc, ECB-enc, OFB-enc, CMAC | — | **-2.7%…+1.1%** (noise) | — |

† B2's HMAC-SHA256 median is taken over 3 runs of which **one stalled** — see
"two findings that are not the fallback" below. Its median is representative but
its spread is not; PBKDF2 and the SHA-256 DRBG, which did not stall in any arm,
carry the SHA-256 lane conclusion.

Counts: A and B are 5 repeats each; B2 is 3. The B2 column's percentages are
computed against the first 3 arm-A runs rather than all 5, so the A medians
behind them differ from the A column by ≤1%; that is smaller than the noise floor
and does not move any conclusion.

B2 carries **zero** duplicate-implementation symbols — it is as strictly
one-implementation as B; the two differ only in which lane was selected. So the
deficit is not the price of running one implementation. **It is the price of
selecting the wrong one.**

The AES signature confirms the mechanism on its own: every mode that has a wide
parallel path lost 43-78% (GCM, CTR, XTS, CBC-dec, CFB-dec, GMAC), and every mode
that is inherently serial and has no wide path to lose moved by less than 3%
(CBC-enc, ECB-enc, OFB-enc, CMAC).

#### 12.1.2 Cause: three lanes the configure-time selection declined on a part that has them

This explains arm B only. The configure-time selection block it describes has
since been removed from `configure.ac`, and CPUID selection at first use
supersedes it; the subsection is kept because it is why arm B's numbers look the
way they do. On a host whose `/proc/cpuinfo` advertises `vaes`, `sha_ni`,
`avx2`, `bmi2` and `adx` it chose:

| Algorithm | Lanes that exist | Configure-time pick | CPUID supports | Cost |
|---|---|---|---|---|
| AES | C, AESNI, AVX1, AVX2, VAES_AVX2, VAES_AVX512 | **AESNI** | VAES_AVX2 | -43…-78% |
| SHA-256 | C, SSE2_SHA, AVX1_SHA, AVX1, AVX1_RORX, AVX2, AVX2_RORX | **AVX2_RORX** | AVX1_SHA | -48…-85% |
| SLH-DSA | C, AVX2 | **C** | AVX2 | -35…-58% |
| SHA-3 | C, BMI2, AVX2 | BMI2 | BMI2 | none (correct) |

The AES comment read *"The VAES lanes are not validated here yet; AESNI is the
lane every AES-NI part runs."* VAES is one lane; the comment was used to skip
`AVX1` and `AVX2` as well, which are not VAES lanes and which arm A's run-time
ladder was in fact selecting on this part. The SLH-DSA comment read *"SLH-DSA has
no accelerated lane to select … both are compiled whatever is named. Only `C`
changes the build"* — and then named `C`, which is the one value the same
sentence says changes the build. It removes `slhdsakey_shake256_*_x4`, the
four-way SHAKE chains, from the module: present in A, absent in B, restored in
B2.

Neither comment is load-bearing evidence and neither was checked against a
measurement. Taking them at face value is what a build reviewer would do, and it
costs half the module's symmetric throughput.

**What survives from this subsection:** selecting a lane the part does not best
support costs 43-85%, and it is invisible unless someone measures it.

#### 12.1.3 Two findings that are not the fallback

Recorded so they are not mis-attributed.

1. **The SHA-NI SHA-256 lane intermittently collapses in kernel space**, to
   ~16 MiB/s against ~5,000 MiB/s — a factor of ~300, same binary, same host,
   run to run. Arm A stalled in **4 of 5** runs, and A also produced an
   intermediate ~220-247 MiB/s regime, i.e. three distinct performance regimes
   from one binary. **This is not caused by the fallback**: arm B2, which carries
   one implementation and no C twin at all, stalled in **1 of 3** runs the same
   way. It follows the SHA-NI lane, not the run-time selector. Arm B
   (`AVX2_RORX`) never stalled in 5 of 5. This needs its own investigation before
   `AVX1_SHA` is relied on anywhere.
2. **ECIES on P-256 is 3.8-5.9x faster in B than in A** (encrypt 12,639 → 75,033
   ops/s), stably in both arms (relative SD ≤1.3%), while ECC keygen, ECDSA sign
   and ECDSA verify are unchanged. No lane change accounts for it, and it is in
   the opposite direction to every primitive ECIES is built from. It is **not**
   claimed as a benefit of the fallback removal; it is an unexplained
   behavioural difference that needs separate investigation.

### 12.2 Run-time A/B: the fallback returns success with no lane

The counting and standards arguments above are about what the module *may*
carry. This is what it *does*, measured, on both branches, with the same probe
binary sources, the same configure line (`--enable-fips=v7 --enable-aesni-with-avx
--enable-sp-asm`, `CFLAGS=-DDEBUG_VECTOR_REGISTER_ACCESS`) and the same forced
failure.

**Method.** Build with `DEBUG_VECTOR_REGISTER_ACCESS`, force
`SAVE_VECTOR_REGISTERS2()` to return `-1002` (`WC_ACCEL_INHIBIT_E`), then run
three approved operations and read their return values. Probe source:
`PQ-FS-dev-area/scripts/pin-cleanup/svr_fallback_probe.c`.

**Branch `...-with-fallback-aug6` — pristine upstream master, run-time fallback
present:**

```
setup complete; forcing SAVE_VECTOR_REGISTERS2() = -1002
  FAIL  RSA-2048 verify              returned 0 under a forced save failure
  FAIL  ECDSA P-256 sign             returned 0 under a forced save failure
  FAIL  ECC P-256 keygen (control)   returned 0 under a forced save failure

RESULT: FAIL (3 silent successes)
```

**Branch `...-withoutfallback` — this work:**

```
setup complete; forcing SAVE_VECTOR_REGISTERS2() = -1002
  ok    RSA-2048 verify              returned -1002
  ok    ECDSA P-256 sign             returned -1002
  ok    ECC P-256 keygen (control)   returned -1002

RESULT: PASS (no operation succeeded without its lane)
```

**What the FAIL arm shows.** On current upstream master an approved RSA-2048
signature verification returns **0, meaning success**, while the vector-register
save that gated its implementation has failed. The operation completed on a
different implementation than the one the dispatch selected, and the return
value carries no indication of that. The Cryptographic Officer cannot
distinguish it from a verification performed on the intended lane. Same for
ECDSA signing and for ECC key generation. This is section 2.1's silent
downgrade, observed rather than argued.

**Why the FAIL arm matters as a control.** It demonstrates the probe can detect
the behaviour it looks for, so the PASS arm is not a test that is simply blind. A
PASS with no corresponding FAIL would prove nothing.

**The shape in the source, without running anything.** In
`wolfcrypt/src/sp_x86_64.c` alone, upstream carries 104 places written as:

```c
if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
    /* fast version */
}
else {
    /* plain C version, which is what runs when the save FAILS */
}
```

The corrected branch carries zero of them. That count is independently
reproducible with a single search of the two branches.

**Scope, stated rather than implied.** The probe runs in **userspace**. The
kernel path is covered by build (all five x86 kernel configurations plus K4
arm32 and K5 arm64), by the gate on the sources kernel and userspace share, and
by a static scan showing no `SAVE_VECTOR_REGISTERS2()` call site is kernel-only
(0 of 215 in `wolfcrypt/src`, 0 in `linuxkm/`; tool
`scripts/pin-cleanup/svr_guard_scan.py`, negative-controlled). It is **not**
covered by this probe executing in-kernel, which would need the module loaded
with fault injection.

### 12.3 The run-time microcode claim, tested

**Claim raised:** the kernel can load new microcode at any time, changing
processor capabilities underneath a running module, and that undefined behaviour
justifies the run-time fallback.

**Verdict: the premise is partly true and the conclusion does not follow. The
fallback cannot respond to this scenario, because the two are keyed on different
events.**

**1. Late microcode loading is real, but it is guarded, loud, and discouraged.**
It exists only under `CONFIG_MICROCODE_LATE_LOADING`
(`arch/x86/kernel/cpu/microcode/core.c:253`, Linux 6.12.59, read directly). The
kernel stops the machine to do it, and its own comment explains why: hyperthread
siblings must be idle and not execute other code, and the update must be
serialised across cores — described in-tree as "conservative and good"
(`core.c:255-264`). `CONFIG_MICROCODE_LATE_FORCE_MINREV` (`core.c:47`) exists to
refuse downgrades.

**2. The kernel already detects a capability change, and says it may not even
take effect.** `microcode_check()` (`arch/x86/kernel/cpu/common.c:2398`)
snapshots processor capabilities, compares them after the update, and on any
difference warns:

```
x86/CPU: CPU features have changed after loading microcode, but might not take effect.
x86/CPU: Please consider either early loading through initrd/built-in or a potential BIOS update.
```

That is the kernel stating that a feature set changed by late loading is **not
reliably in force**. It also taints (`TAINT_CPU_OUT_OF_SPEC`, `common.c:1660`).
A machine in that state is outside its specified operating envelope, which for a
FIPS operating environment is a configuration defect, not a scenario the module
is expected to paper over at run time.

**3. The decisive point — the fallback is not connected to this event.** The
fallback triggers on a **vector-register save failure**. It does not trigger on a
CPUID capability change, and it cannot: nothing re-reads CPUID.
`cpuid_set_flags()` (`wolfcrypt/src/cpuid.c`) populates the flag word exactly
once — guarded by `if (WOLFSSL_ATOMIC_LOAD(cpuid_flags) == WC_CPUID_INITIALIZER)`
— and `cpuid_get_flags()` returns that cached word thereafter.

Walk the claimed scenario through the actual code. Microcode is loaded and, say,
AVX2 disappears:

* the module's cached `cpuid_flags` still says AVX2 is present;
* the dispatch therefore still selects the AVX2 routine;
* `SAVE_VECTOR_REGISTERS2()` still succeeds — saving vector state has nothing to
  do with whether AVX2 decodes;
* the AVX2 instruction then executes and faults (#UD).

The fallback never fires. It is downstream of an event that never occurs. A
mechanism keyed on save failure cannot protect against instruction
disappearance, and no arrangement of it can, because the two events are
unrelated.

**4. What would address it,** if anyone judged the scenario worth addressing, is
re-reading CPUID after a microcode event and re-dispatching — which is a
different mechanism, is not what the fallback does, and would itself be a
run-time implementation switch of the kind IG 10.3.A makes expensive. The
cheaper and standard answer is the one the kernel itself recommends: load
microcode early, through initrd or built-in, so the capability set is settled
before the module initialises.

**5. Testability.** This claim does not need a soak to settle. It is decided by
reading the dispatch: no CPUID re-read exists, so no microcode-induced capability
change can reach the fallback. A demonstration is nevertheless available: trigger
a late load via `/sys/devices/system/cpu/microcode/reload` on a
`CONFIG_MICROCODE_LATE_LOADING` kernel while the module runs, and observe that
(a) `microcode_check()` reports whether capabilities moved, (b) the module's
cached `cpuid_flags` is unchanged either way, and (c) no
`SAVE_VECTOR_REGISTERS2()` failure is produced by the event. **Not run here** —
stated as the procedure, not as a result.

### 12.4 Every justification offered has been tested as it was raised

| Account given for the fallback | Outcome |
|---|---|
| "The softirq hangs came from the operating environment" | traced to a one-line `pid 0` check in our own code (section 2) |
| "The failures came from heavy filesystem load and processor contention" | tested under sustained load; **did not reproduce** |
| "Deferred interrupt work can never use these registers" | the kernel's own rule permits it; removing our extra condition made the work succeed |
| "Microcode can change capabilities at run time" | answered by reading the dispatch (section 12.3); the fallback is keyed on a different event |

None has survived. That is a statement about the arguments, not about anyone who
made them. It matters because the case for keeping the mechanism does not
currently rest on any demonstrated failure that only it addresses.

### 12.5 Corrupting SSPs and CSPs produced no failure — the module hid it

SSPs and CSPs were corrupted directly in memory with the kernel debugger while
the module was running. **Nothing failed. Nothing was reported.** The module
continued to return results, and the Cryptographic Officer was given no status
indicator that anything had gone wrong.

That is the fallback design doing exactly what it was built to do. When the
selected implementation produced a wrong or unusable result, control moved to
another implementation of the same algorithm and the operation succeeded. The
corruption was real, the failure was real, and both were absorbed silently.

This is a FIPS violation on its own terms, independent of the one-implementation
rule:

* An error condition arose and **no error indicator was output**. The
  Cryptographic Officer cannot observe, log, or act on a failure the module
  refuses to report.
* The module continued offering approved services **after** an integrity failure
  in its own key material, rather than transitioning to an error state.
* The result returned to the caller came from an implementation the Cryptographic
  Officer did not select and cannot identify after the fact.

**`rng_bank` was the worst offender.** Corrupting a bank instance's state did not
surface as a DRBG failure: the request was served from a different instance and
the caller received bytes as though nothing had happened. A DRBG that answers
after its state has been corrupted, without saying so, is the most damaging
possible place for this behaviour — every key derived downstream inherits the
silence.

A failure that cannot be observed is worse than a failure. It converts a
detectable fault into an undetectable one, which is the opposite of what a
self-test-bearing module exists to do.

### 12.6 Duplicate implementations carried without a governing CAST

Multiple algorithms ship more than one implementation in a single build, with
**one CAST covering the set**. A CAST exercises one path; the others are
unverified code. Nothing tests them, and nothing reports which one served a
request.

**SHA-512 is the worst case: five implementations present at once** on x86_64:

| # | implementation | declared | selected |
|---|---|---|---|
| 1 | `_Transform_Sha512` | `sha512.c:1201` | `:1465` (default) |
| 2 | `Transform_Sha512_AVX1` | `:1172` | `:1455` |
| 3 | `Transform_Sha512_AVX1_RORX` | `:1179` | `:1446` |
| 4 | `Transform_Sha512_AVX2` | `:1176` | `:1433` |
| 5 | `Transform_Sha512_AVX2_RORX` | `:1182` | `:1424` |

Selection is through the `Transform_Sha512_p` function pointer (`sha512.c:1379`),
called at `:1392` and assigned in `Sha512_SetTransform()` at `:1424-1465`. All of
it sits in the `!WC_NO_INTERNAL_FUNCTION_POINTERS` arm. RORX is what takes the
count from three to five: both RORX variants arrive with `HAVE_INTEL_AVX2`.

**Nothing counts or self-tests this set.** `WC_SHA512_IMPL_COUNT`,
`WC_SHA256_IMPL_COUNT`, `WC_SHA512_N_RORX` and `WC_SHA512_PINNED` have **no
definer anywhere in this tree**. Five implementations are compiled, one CAST
covers them, and that is precisely the contained-versus-reachable question of
section 3.1.1.

Other architectures add `Transform_Sha512_crypto_aarch64`, `_neon_aarch64`,
`_Len_riscv_crypto`, `_Len_riscv_vector` and `_base`, but those are mutually
exclusive by target, so five is the number present at once in a single build.

**This is not only an x86 story.** On aarch64, `sha256.c:1385`/`:1390` select
between `Transform_Sha256_Len_crypto_aarch64`, `_neon_aarch64` and the C
`Transform_Sha256_Len` from CPUID, and `aes.c:1232` sets
`aes->use_aes_hw_crypto = IS_AARCH64_AES(cpuid_flags)`. Under section 3.0 that
is the sanctioned construct, not a finding.

This section counts implementations *contained*; section 3.1.1 counts the one
*reachable* per operating environment, and the CAST set covers the reachable
one. Read the two together or this section overstates.

The two findings compound: duplicate implementations create the fallback target,
and the fallback conceals the failure that would otherwise expose them.

### 12.7 Open: automate the SSP/CSP corruption reproducer

Section 12.5 was produced by hand under a kernel debugger. It needs to become a
repeatable harness before it can carry the weight the rest of this document's
evidence does. The manual procedure, as performed:

1. Start the debugger and set breakpoints **before** `insmod`.
2. Break on any SSP/CSP-bearing API — sign, verify, key generation, key
   validation, encrypt, decrypt.
3. When the breakpoint hits, single-step until past the point where private or
   public key material is live in stack or heap.
4. Corrupt the key material by overwriting it with `0xDEADBEEFDEADBEEF`,
   repeated. The pattern is a multiple of 4 bytes so a 16-byte AES key is easy to
   count off; where the target is not a clean multiple, truncate the tail
   (`DEADBE`, dropping the `EF`).
5. Delete every breakpoint and release the module to run normally.

**Observed:** operations still succeeded. The failures were intercepted at the
linuxkm glue layers, discarded, and replaced with results from a working fallback
implementation.

**Unresolved, and not to be written up as settled until it is:** no degraded mode
was observed. `fips.c` / `fips_test.c` would be expected to transition the module
on a failure of this kind. Two hypotheses, neither yet tested:

* linuxkm-specific code in `fips.c` or `fips_test.c` is overriding or bypassing
  the degraded-mode transition; or
* the module *did* degrade and the indication never reached `dmesg`.

Those have opposite consequences — the first is a second FIPS violation, the
second is a reporting gap — so the harness must distinguish them, not just
reproduce the silent success. Reading `fipsMode` and the CAST status table
directly after the corruption, rather than relying on log output, is what
separates them.

**Automation feasibility:** the matrix already boots every kernel operating
environment under `qemu-system-*`, and QEMU exposes a gdbstub (`-s -S`), so
breakpoints, single-stepping and memory writes are all scriptable from a gdb
batch script against the guest. The parts needing care are locating the key
material without symbols for stack temporaries, and making the corruption
deterministic across runs. Target: one cell per corruption site, each with a
negative control (an uncorrupted run that must still pass) so a harness that
silently fails to corrupt anything cannot be mistaken for a module that survived
corruption.

### 12.8 Sources

**Kernel source, read directly.** This document cites **two kernel versions**.
Each section names its own; checking a citation against the other version
reports a false miss (for example `kernel/softirq.c:342` is
`__preempt_count_add(cnt)` in 6.12.59 and a comment opener in 6.6.99). Verify
against the version the surrounding text names.

| Claim | Where |
|---|---|
| The operating environment's FPU rule has no task-identity / pid condition | `arch/x86/kernel/fpu/core.c:irq_fpu_usable()` |
| On x86 `may_use_simd()` *is* `irq_fpu_usable()` | `arch/x86/include/asm/simd.h` |
| Ordinary kernel C cannot emit vector instructions | `arch/x86/Makefile` — `KBUILD_CFLAGS += -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx` |
| The save may be refused and the caller must check | `arch/x86/include/asm/fpu/api.h` |
| The `local_bh_enable()` bracket is illegal in hardirq | `kernel/softirq.c:__local_bh_enable_ip()` — `WARN_ON_ONCE(in_hardirq())`, `lockdep_assert_irqs_enabled()` |
| The crypto-API DRBG is process-context by design | `include/crypto/drbg.h:115`; `crypto/drbg.c:drbg_generate_long()`; `crypto/rng.c:crypto_get_default_rng()` |
| `get_random_bytes()` does not use the crypto API | `drivers/char/random.c` — zero `crypto_alloc_*`, zero `stdrng` |
| `stdrng` consumers are a short named list | `crypto/dh.c`, `crypto/ecc.c`, `crypto/geniv.c`, `net/tipc/crypto.c`, two hardware drivers |
| `kernel_fpu_begin_mask()` disables preemption only, not bottom halves | `arch/x86/kernel/fpu/core.c` — why we call `local_bh_disable()` ourselves |
| The default "may I use SIMD", stricter, used by 32-bit Arm | `include/asm-generic/simd.h` — `return !in_interrupt();` |

**Standards.**

| Requirement | Source |
|---|---|
| Each implementation of one algorithm CAST'd separately | FIPS 140-3 IG 10.3.A, General CAST requirements, **GeneralNote1**, p.100 (IG 16 Apr 2026; section last modified 27 Feb 2026) |
| Same, for several implementations of one core algorithm | FIPS 140-3 IG **10.3.B** ("Self-test for Embedded Cryptographic Algorithms"), **Additional Comments 1**, p.103 — NOT 10.3.A, whose own Additional Comment 1 (p.101-102) is about pairwise consistency tests |
| Accelerated algorithms tested with and without PAA | FIPS 140-3 IG **2.3.C**, Resolution and Testing requirements |
| No data output before pre-operational self-tests pass | ISO/IEC 19790:2012 §7.10.1 `[10.03]` |
| Self-tests pass before operational state | ISO/IEC 19790:2012 §7.10.2.1 `[10.15]` |
| Loaded code withholds approved functions until self-tests pass | ISO/IEC 19790:2012 §7.2.4.2 `[04.31]` |
| CAST before first operational use | ISO/IEC 19790:2012 §7.10.3.2 `[10.27]` |

**Resolvable links.** Every citation above is given by document, section and page
so a reviewer with the PDFs open can check it directly. This table is the
clickable form of the same references.

| Reference | Link |
|---|---|
| CMVP program home | https://csrc.nist.gov/projects/cryptographic-module-validation-program |
| FIPS 140-3 (standard) | https://csrc.nist.gov/pubs/fips/140-3/final |
| FIPS 140-3 Implementation Guidance | https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-standards |
| ISO/IEC 19790:2012 | https://www.iso.org/standard/52906.html |
| ISO/IEC 24759:2017 (TE tags) | https://www.iso.org/standard/72515.html |
| SP 800-90A Rev.1 (DRBG) | https://csrc.nist.gov/pubs/sp/800/90/a/r1/final |
| SP 800-208 (stateful hash-based signatures) | https://csrc.nist.gov/pubs/sp/800/208/final |
| FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| FIPS 204 (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final |
| FIPS 205 (SLH-DSA) | https://csrc.nist.gov/pubs/fips/205/final |
| Cert #4718 (module v5.2.1) | https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718 |
| Cert #3389 security policy | https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3389.pdf |
| Cert #2425 | https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/2425 |
| Kernel-mode floating point and SIMD rules | https://docs.kernel.org/core-api/floating-point.html |
| Locking primitives and what each guarantees | https://docs.kernel.org/locking/locktypes.html |
| Per-processor variable operations | https://docs.kernel.org/core-api/this_cpu_ops.html |
| Linux stable v6.12.59 source | https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/?h=v6.12.59 |
| Linux stable v6.6.99 source | https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/?h=v6.6.99 |
| Bernstein, cache-timing attacks on AES (2005) | https://cr.yp.to/antiforgery/cachetiming-20050414.pdf |
| Osvik, Shamir and Tromer, cache attacks and countermeasures (2006) | https://eprint.iacr.org/2005/271 |
| PR #8840 — origin of the per-core DRBG bank (section 11) | https://github.com/wolfSSL/wolfssl/pull/8840 |
| PR #11031 — arm32 `getauxval()` guard | https://github.com/wolfSSL/wolfssl/pull/11031 |

**Module source, read directly.**

| Claim | Where |
|---|---|
| A nested save can fail three ways | `linuxkm/x86_vector_register_glue.c:wc_save_vector_registers_x86()` |
| `Transform_Sha512_Len()` has no early exit above its switch (non-fallback build) | `wolfcrypt/src/sha512.c` |
| `inline_XTRANSFORM()` early exit tests only `sha_method == SHA256_C` | `wolfcrypt/src/sha256.c` |
| AES-XTS is an approved service here | `fips.c` — `wc_AesXtsEncrypt_fips()` and siblings |
| Certified builds refuse the fallback | `wolfssl/wolfcrypt/settings.h`, `wolfssl/wolfcrypt/fips.h`, both `#error` |
| The bank holds DRBG instances, no output bytes | `rng_bank.h:68-100`; `rng_bank.c` — no buffer/cache/pool/prefill/refill; sole `wc_RNG_GenerateBlock()` at `:986` discards 4 bytes to force a reseed |
| Four wrong-answer defects from shared dual implementations | `stress/README.md` |
| The table-driven AES and its cache setting | `wolfcrypt/src/aes.c:2006` (`Te[4][256]`), `:92` (option doc), `:2699` / `:3046` (`PreFetchTe()`) |
| Processor capability word, filled once | `wolfcrypt/src/cpuid.c` |
| Continuous integration gate | `scripts/fips-no-svr-fallback-check.sh` |

---

## 13. The lanes — which implementation runs, and when that is decided

A **lane** is one implementation of one algorithm. Under section 3.0 a
PAA-configured build contains several lanes per algorithm and reaches exactly one
of them on a given processor, chosen once from CPUID at first use. What makes
section 1's rule enforceable is that a vector-register save failure returns an
error: there is nothing the module will substitute, so the failure propagates to
the Cryptographic Officer instead of being absorbed.

Compiling only one lane — posture 2, configured without PAA — narrows *contained*
to one as well as *reachable*. It is not required under the elected posture, and
it is the fallback answer if the laboratory insists on the contained reading.

### 13.1 The early-DRBG constraint

The DRBG is the one algorithm that cannot wait, and this constraint is about
**availability**, not about the CAST set. CPUID stepping selects a lane from what
the processor reports, but whether that lane is *usable* in a given context
depends on whether the vector registers can be saved — and early in boot, or in
softirq, they may not be. With no fallback, a DRBG whose hash latched to a vector
lane returns an error there rather than producing output.

So if a build wants its DRBG available before the fast lane is usable, the DRBG's
underlying hash must be **native C for the entire life of the module** — not C
first and PAA later. Switching lanes mid-life is the fallback pattern under a
different name: two implementations of one algorithm, selected at run time, with
no indicator telling the Cryptographic Officer which one produced a given output.

With two fully compliant DRBGs — SHA-256-based and SHA-512-based — a build can
fix *one* hash to C for early availability and accelerate everything else. That
gives an almost-fully-PAA build without reintroducing run-time selection
anywhere.

### 13.2 The three supported linuxkm builds

```
--enable-fips=v7 --enable-aesni-with-avx --enable-linuxkm=earlydrbg-sha256
    SHA-256 never gets PAA; everything else does.  DRBG available early.

--enable-fips=v7 --enable-aesni-with-avx --enable-linuxkm=earlydrbg-sha512
    SHA-512 never gets PAA; everything else does.  DRBG available early.

--enable-fips=v7 --enable-aesni-with-avx --enable-linuxkm
    No early DRBG requested.  Both hashes take the fast lane, and the DRBG
    inserts once that lane is available.
```

> **`earlydrbg-sha256` and `earlydrbg-sha512` are not implemented.** The two
> option strings appear nowhere in `configure.ac`, `settings.h` or `linuxkm/` —
> only in this file. Section 13.1's constraint is real and the build shapes above
> are the right answer to it, but no configure mechanism expresses it today.
> **Two of the three builds cannot be configured.** Build them before any of this
> is shown to a laboratory or repeated in a Security Policy; a reviewer who tries
> the command line will find out in one step.

The first two trade one hash's acceleration for early DRBG availability; the
third trades early availability for full acceleration. What none of them do is
start on one implementation and move to another. Each of the three is available
in either posture — with PAA, where the remaining algorithms step on CPUID, or
software-only.

---

## 13.3 The cross-CPU slot scan

**Scope first: this is not compiled into a certified module.** The scan lives in
`wc_linuxkm_fpu_state_assoc()`, which is part of the arbitration arm described in
section 13.4 — built only for non-FIPS and the uncertified development flavours.
A certified build has no slot table for it to search. It is analysed here because
it is upstream's code, because a development build still carries it, and because
it is the third instance of the pattern in Appendix A.1.

**Summary.** The scan is a cross-CPU search that relocates a thread's
vector-register slot between processors. The state it recovers from cannot occur,
because the kernel's own locking forbids it. If it ever did occur, the recovery
would corrupt the per-CPU bracket accounting rather than repair it. This is the
fallback pattern again: **unbounded defensive machinery erected against an
unproven hypothetical, where the machinery is itself unsound.**

### 13.3.1 What the code does

`linuxkm/x86_vector_register_glue.c`, `wc_linuxkm_fpu_state_assoc_unlikely()`,
the `create_p == 0` branch — the call `wc_restore_vector_registers_x86()` makes:

```c
for (cpu_i = 0; cpu_i < wc_linuxkm_fpu_states_n_tracked; ++cpu_i) {
    if (states[cpu_i].in_use &&
        states[cpu_i].pid == my_pid &&
        states[cpu_i].ctx == my_ctx)
    {
        wc_linuxkm_fpu_states[my_cpu] = wc_linuxkm_fpu_states[cpu_i]; /* relocate */
        states[cpu_i].fpu_state = 0;
        states[cpu_i].in_use    = 0;
        return &wc_linuxkm_fpu_states[my_cpu];
    }
}
```

On a local miss it scans every processor's slot, and on a match **moves** the
slot to the current processor and returns it non-NULL. The only state this can
serve is a thread that took its bracket on one processor and is completing it on
another.

### 13.3.2 That state cannot occur — three configurations, all closed

A bracket is opened in exactly two places, and both disable migration before
`this_cpu_inc(wc_svr_bracket_depth)`:

| Configuration | What prevents migration |
| :--- | :--- |
| `CONFIG_PREEMPT_COUNT` (ordinary) | `local_bh_disable()` raises `preempt_count`; a task with preemption disabled is not migrated |
| `CONFIG_PREEMPT_RT` | explicit `preempt_disable()` — on RT, `local_bh_disable()` does not disable preemption |
| `CONFIG_SMP && !CONFIG_PREEMPT_COUNT` | explicit `migrate_disable()` — there `preempt_disable()` is a bare `barrier()` |

This holds on the inhibited path as well, which takes `local_bh_disable()` but
never calls `kernel_fpu_begin()`. Independently, for every non-inhibited bracket
the kernel supplies the same guarantee: `kernel_fpu_begin_mask()` opens with
`preempt_disable()` and `kernel_fpu_end()` closes with `preempt_enable()`
(`arch/x86/kernel/fpu/core.c:421-423`, `:446-451`, read directly, Linux 6.6.99
and 6.1.62).

**A thread cannot be on a different processor at restore than it was at save
while holding a bracket.** The scan searches for a condition the locking
excludes.

### 13.3.3 The evidence, quoted rather than argued

The claim "a task cannot migrate while holding the bracket" is not an argument
made here; it is a documented kernel guarantee.

**1. Preemption-disable is how the kernel prevents migration.**
`Documentation/locking/locktypes.rst`, lines 252-255 (Linux 6.6.99):

> "Tasks holding a spinlock_t do not migrate. **Non-PREEMPT_RT kernels avoid
> migration by disabling preemption.** PREEMPT_RT kernels instead disable
> migration, which ensures that pointers to per-CPU variables remain valid even
> if the task is preempted."

**2. `migrate_disable()` pins the task.** Same file, lines 439-441:

> "migrate_disable() ensures that the task is **pinned on the current CPU**
> which in turn guarantees that the per-CPU access to var1 and var2 are staying
> on the same CPU while the task remains preemptible."

**3. Preemption-disable is a CPU-local guarantee.** Same file, lines 58-61:

> "disabling preemption or interrupts are **pure CPU local concurrency control
> mechanisms** and not suited for inter-CPU concurrency control."

Which is exactly why a *cross-CPU* recovery for a CPU-local bracket is
category-mismatched: the bracket counter is `DEFINE_PER_CPU` and the scan moves
its owner between processors without moving the count.

**4. `local_bh_disable()` raises `preempt_count` on non-RT.**
`kernel/softirq.c:327-335`, the non-PREEMPT_RT `__local_bh_disable_ip()`:

```c
raw_local_irq_save(flags);
__preempt_count_add(cnt);
```

and the softirq count is a field *inside* `preempt_count`
(`include/linux/preempt.h:30-48`: `SOFTIRQ_SHIFT`, `SOFTIRQ_MASK`), so raising it
disables preemption — and by citation 1, prevents migration.

**5. `kernel_fpu_begin()` disables preemption for the life of the section.**
`arch/x86/kernel/fpu/core.c:421-423` and `:446-451`:

```c
void kernel_fpu_begin_mask(unsigned int kfpu_mask) { preempt_disable(); ... }
void kernel_fpu_end(void) { ...; preempt_enable(); }
```

An independent second guarantee for every non-inhibited bracket, supplied by the
kernel without the module asking.

**Resolvable links**, pinned to v6.6.99 and equally checkable at v6.1.62:

| Citation | Link |
|---|---|
| `Documentation/locking/locktypes.rst` (rendered) | https://www.kernel.org/doc/html/v6.6/locking/locktypes.html |
| `locktypes.rst` (source, pinned) | https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/locking/locktypes.rst?h=v6.6.99 |
| `arch/x86/kernel/fpu/core.c` | https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kernel/fpu/core.c?h=v6.6.99 |
| `kernel/softirq.c` | https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/softirq.c?h=v6.6.99 |
| `include/linux/preempt.h` | https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/preempt.h?h=v6.6.99 |

**Standard of proof applied here.** Each of the three configurations is closed by
a quoted kernel guarantee, not by inference from behaviour. The protections the
cross-CPU scan asserts were necessary are therefore not merely unproven — the
opposite proposition is documented by the kernel, in a file whose stated purpose
is to tell driver authors which primitive gives which guarantee.

### 13.3.4 If it ever fires, it manufactures the corruption

`wc_svr_bracket_depth` is `DEFINE_PER_CPU`; it is raised with `this_cpu_inc()`
and lowered with `this_cpu_dec()`. The scan returns non-NULL, so the caller takes
the ordinary outermost-restore unwind:

```c
wc_linuxkm_svr_bracket_dec();   /* this_cpu_dec -- CPU B */
local_bh_enable();              /* CPU B */
```

If the slot was relocated from CPU A to CPU B, then:

* `bracket_depth[A]` remains raised **permanently**. A later thread on CPU A will
  find "no slot, bracket > 0" and take the recovery branch.
* `bracket_depth[B]` is lowered for a bracket never taken there, and
  `local_bh_enable()` is issued on a processor where this thread never disabled
  softirqs.

The recovery therefore **creates** a cross-CPU bracket mismatch out of a
situation that could only have arisen from a prior defect. It does not repair a
leak; it converts a contained one into a distributed one.

### 13.3.5 Why this matters beyond correctness

For a validated cryptographic module the cost is not confined to this function:

1. **Boundary surface.** Every such structure is code inside the module boundary
   that a reviewer must read, a laboratory must be satisfied by, and a CAST
   regime must account for. It is paid for at every submission, not once.
2. **Unreachable code is unverifiable code.** The scan cannot be exercised by any
   test that respects the locking, so its defect was found by reading, not by
   testing — and would not have been found by any amount of running.
3. **Complexity is the vulnerability substrate.** Concurrency scaffolding that
   mutates shared per-CPU state on a path nobody can reach is precisely where
   latent flaws accumulate: no coverage, no reproducer, and reviewers deterred by
   the surrounding commentary.
4. **Reviewer trust is the asset.** A vendor whose module contains defensive
   machinery for impossible states invites the question of what else was assumed
   rather than verified. That question is expensive to answer and difficult to
   un-ask.

### 13.3.6 A comment that argued the opposite of the code

The block comment preceding the recovery branch asserted that "a matching slot,
or no slot at all, still does not prove the bracket belongs to THIS frame rather
than an outer one of the same task." The first clause is false as a matter of
control flow: a matching slot causes `wc_linuxkm_fpu_state_assoc()` to return it
non-NULL — including via the cross-CPU scan — so the recovery branch is not
entered in that case. The comment now describes the actual control flow.

**Treat commentary in this module as an unverified claim.** Several structures
here carry prose asserting a necessity the code does not exhibit. That applies to
comments written by anyone, including previous reviewers of this document.

### 13.3.7 Recommendation

Delete the cross-CPU scan and return NULL on a local miss. The caller already
handles NULL, and does so correctly: it refuses to unwind when this processor's
slot belongs to another `(pid, ctx)`, and otherwise lowers a bracket that — by
the locking above — can only be its own. That is strictly safer than relocating a
slot across processors and desynchronising the per-CPU accounting.

**This is a behavioural change and is not yet applied. It is not a submission
blocker**, because the scan is not compiled into a certified module. It is
upstream's code; removing it changes restore behaviour for every non-FIPS
consumer, so it should be taken up with upstream rather than diverged locally. It
requires a module rebuild, the kernel operating environment cells, and a stress
run before it goes anywhere near a release branch.

### 13.3.8 Limits of this analysis

* The migration argument was derived from Linux 6.6.99 and 6.1.62. The operating
  environment kernel configurations have **not** each been enumerated to confirm
  that one of the three guarantees above always applies.
* It is established that the scan cannot find the slot of a **live
  bracket-holder**. It is not established that the scan is never entered at all —
  it can still encounter genuinely stale slots, which is exactly where the
  accounting mismatch above would occur.
* No reproducer exists for section 13.3.4. It is derived from the per-CPU
  semantics of `this_cpu_inc` / `this_cpu_dec` against the relocation, not
  observed in a run.

---

## 13.4 The per-CPU slot table and ownership arbitration

**What a certified module contains: a reference count, and nothing else.**
`linuxkm/x86_vector_register_glue.c` carries two implementations of the
save/restore glue, chosen at compile time. v5, v6, v7 and FIPS Ready take the
minimal one:

```c
/* Certified builds do only what the kernel asks of a caller. */
struct wc_svr_cpu_state {
    unsigned int depth;
    unsigned int inhibited;
};
static DEFINE_PER_CPU(struct wc_svr_cpu_state, wc_svr_state);
```

That is four functions and a two-field per-CPU struct. **No slot table, no pid
or ctx tracking, no staleness clock, no reclaim, no cross-CPU search.** It is
exactly the obligation `Documentation/core-api/floating-point.rst` places on a
caller and no more, which is section 1's rule applied to this file.

The ownership arbitration described in the rest of this section is compiled
**only** for non-FIPS builds and the uncertified development flavours
(`--enable-fips=dev`, `dev-no-post`). It is recorded here because it is the
fourth instance of the pattern in Appendix A.1, and because anyone building a
development flavour still gets it.

| symbol | arbitration arm | certified arm |
|---|---:|---:|
| `wc_linuxkm_fpu_states` | 33 | **0** |
| `wc_linuxkm_fpu_state_assoc` | 20 | **0** |
| `claimed_at` | 11 | **0** |
| `WC_FPU_SLOT_STALE_JIFFIES` | 4 | **0** |
| `find_get_pid` | 4 | **0** |
| `states[cpu_i]` (the cross-CPU scan of section 13.3) | 6 | **0** |

**Gate, and what it does not yet cover.** The split was verified two ways: the
preprocessor conditional at the head of the file pairs its `#else` with the
opening `#if` at file scope, computed by depth tracking rather than read by eye;
and the symbol census above was taken across the two line ranges. It has **not**
been confirmed against a built certified module — no `.ko` in the tree postdates
the change. Run that gate before quoting this section to a laboratory, and
negative-control it against a `--enable-fips=dev` build, where every symbol above
must appear.

### 13.4.0 What the arbitration did, in the builds that have it

The arbitration arm keeps a per-CPU table, `wc_linuxkm_fpu_states[]`, recording
which `(pid, ctx)` holds a save/restore bracket on each processor and how deep
its recursion is. When a claimant finds the slot for its processor already
occupied, the module decides whether the existing entry is stale and, if it
decides yes, takes it. Three arms do this: a dead-pid reclaim, a time-bounded
reclaim for a live nonzero pid, and a reclaim for pid 0 (the idle task).

**The question is not whether those arms are correctly written. It is whether
making that judgement is the module's business.** The answer below is why the
certified build does not make it.

### 13.4.1 What the kernel documents as the module's job

`Documentation/core-api/floating-point.rst` is the kernel's module-facing
document for kernel-mode floating point and SIMD. Four sentences bound the
contract:

> "They are **not** required to be reentrant. **If the caller expects to nest
> critical sections, it must implement its own reference counting.**"

> "It is only valid to call `kernel_fpu_begin()` after a previous call to
> `kernel_fpu_available()` returned true."

> "Preemption may be disabled inside critical sections, so **their size should
> be minimized**."

> "These functions are only guaranteed to be callable from (preemptible or
> non-preemptible) **process context**."

Three consequences.

**(a) A recursion counter is documented-correct.** wolfSSL calls
`SAVE_VECTOR_REGISTERS()` at many levels of its own call graph, and the kernel
forbids nesting `kernel_fpu_begin()`. The documentation tells the caller to
reference-count, so the module keeping a depth count is exactly right and is not
in question.

**(b) The documentation says "its OWN reference counting."** That is a count of
the caller's own nesting. What was implemented is a per-CPU ownership registry,
which must answer "whose entry is this?" and then act when the answer is "not
mine." That question does not exist in the documented model. A per-caller counter
cannot hold another task's stale entry, because there is no shared registry to
leave one in. **The arbitration existed because the structure was scoped to the
processor rather than to the caller.**

**(c) There is no documented way for a module to ask who owns the vector
registers right now.** `kernel_fpu_available()` reports platform capability, not
current ownership. `may_use_simd()` and `irq_fpu_usable()` do carry the
information, but they are architecture-internal and appear nowhere in the
module-facing documentation. A module that needs an ownership query has left the
interface.

No kernel documentation describing a per-CPU FPU ownership table, or an eviction
policy for one, was found in `core-api`, in the crypto documentation, or in the
arm64 documentation index, where the old kernel-mode-NEON page no longer exists.
Absence of documentation is not a prohibition, but for the question "is this ours
to do", the absence of any documented mechanism is itself informative.

### 13.4.2 A reclaim revokes nothing

Checked across the whole reclaim block: **no reclaim arm calls
`kernel_fpu_end()` or `kernel_neon_end()`.** A reclaim rewrote this module's
table and left the kernel's own state untouched.

The kernel's state is the authority. `DEFINE_PER_CPU(bool, in_kernel_fpu)` is
written only by `kernel_fpu_begin_mask()` and `kernel_fpu_end()`, and read by
`irq_fpu_usable()` (`arch/x86/kernel/fpu/core.c`, unchanged across 4.18.9, 6.6.99
and 6.12.59). arm64 has the equivalent in per-CPU `fpsimd_context_busy`.

So an eviction is a bookkeeping assertion about a resource the module does not
own and cannot release.

### 13.4.3 What was measured

Harness: `matrix/svr-pid0/`. It plants a known occupant in one processor's slot
and drives a real SHA-256 on that processor through the kernel crypto API. Three
builds (unmodified, arm removed, arm time-bounded), proven distinct by source
hash, on a `CONFIG_PROVE_LOCKING` + `CONFIG_DEBUG_ATOMIC_SLEEP` kernel. Two of
the five arms are controls and both held in every column; no kernel splat in any
arm.

| planted in the processor's slot | unmodified | arm removed | arm time-bounded |
| :--- | :--- | :--- | :--- |
| idle task, claimed just now | **TAKEN** | REFUSED | REFUSED |
| idle task, claimed 6 s ago | TAKEN | REFUSED | TAKEN |
| **a real leak** (FPU section left open, `fpu_state` set) | REFUSED | REFUSED | REFUSED |
| *control:* a live nonzero pid | REFUSED | REFUSED | REFUSED |
| *control:* an exited pid | TAKEN | TAKEN | TAKEN |

**Row 1 is the concrete defect.** The unmodified module evicted a slot claimed one
millisecond earlier, 20 attempts out of 20. A slot that new is not plausibly
abandoned. This is observed rather than argued.

**Row 3 is the one that matters for the design question.** A slot leaked by a save
with no restore has `fpu_state` nonzero and leaves `in_kernel_fpu` set on the
processor. Plant that and every build refuses, because `may_use_simd()` refuses
the caller before any slot code runs. The module logged `nonzero preempt_count
0x1 on CPU 1`, and the time-bounded build logged **zero** pid-0 reclaims on that
arm against 20 on the synthetic arm above it.

**So the reclaim does not fire on the state a real leak produces.** It fires on a
state the harness had to fabricate. The one state where a time bound would help
is a slot leaked with the FPU section properly closed, which requires the
inhibited path, whose entry point `DISABLE_VECTOR_REGISTERS()` is defined but
never invoked anywhere in either repository.

### 13.4.4 Why a timeout could never have been the answer

Every claim site is immediately followed by `this_cpu_inc(wc_svr_bracket_depth)`
with no early return between them, and the release sites pair the same way. So a
leaked slot leaks the depth counter with it: **a leak and a live bracket are
identical in every field the module records.** Elapsed time is the only quantity
that differs. A timeout was not a chosen discriminator; it was the only one the
data structure left available.

The five-second constant had no measured basis. The comment defending it argued
that a bracket is "milliseconds at worst" because the longest operation is an
SLH-DSA or ML-DSA sign. Nobody timed one under a bracket. That comment now
states what the constant is and that it is unmeasured.

### 13.4.5 What actually keeps an intruder out: `may_use_simd()`

`wc_save_vector_registers_x86()` tests `may_use_simd()` **before** any slot is
touched. That test, not any argument about preemption counts, is what refuses an
intruder:

| Operating environment | `may_use_simd()` resolves to | Detects another task's live section on this processor? |
| :--- | :--- | :--- |
| K1/K2/K3 x86 | `irq_fpu_usable()`, reading per-CPU `in_kernel_fpu` (`arch/x86/include/asm/simd.h`; `arch/x86/kernel/fpu/core.c:58-77`) | **Yes** — returns false, save returns `WC_ACCEL_INHIBIT_E` |
| K5 arm64 | per-CPU `fpsimd_context_busy` (`arch/arm64/include/asm/simd.h`) | **Yes** — and `kernel_neon_begin()` additionally has `BUG_ON(!may_use_simd())` (`arch/arm64/kernel/fpsimd.c:1909`) |
| K4 arm32 | `IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !in_hardirq()` (`arch/arm/include/asm/simd.h`) | **No** — and `kernel_neon_begin()` checks only `BUG_ON(in_hardirq())` (`arch/arm/vfp/vfpmodule.c:829`) |

So on four of the five kernel operating environments the reclaim **cannot execute
against a live owner**: the kernel refuses the caller upstream of it. On Arm the
`(preempt_count() == 0) || may_use_simd()` test short-circuits for an intruder
(its own count is zero, see below), so on arm64 the refusal comes from the
`BUG_ON` inside `kernel_neon_begin()` rather than from the `||`.

**A comment here claimed a proof it did not have.** It argued that on a
non-PREEMPT_RT kernel reaching `preempt_count_add()`, `preempt_count()` is
nonzero and nothing else can be scheduled on that processor, and concluded "It is
a proof, not a heuristic." The narrow half is true —
`include/linux/bottom_half.h:11-15` inlines `preempt_count_add(cnt)` on
non-RT/non-`TRACE_IRQFLAGS`, and `preempt_count_add` is defined at
`include/linux/preempt.h:194-203`, **outside** the `#ifdef CONFIG_PREEMPT_COUNT`
block. The inference does not follow, for two independent reasons.

**1. `preempt_count()` is per-processor only on x86.**

| architecture | storage | file |
| :--- | :--- | :--- |
| x86 | `raw_cpu_read_4(pcpu_hot.preempt_count)` — **per-CPU** | `arch/x86/include/asm/preempt.h:25-28` |
| arm64 | `READ_ONCE(current_thread_info()->preempt.count)` — **per-task** | `arch/arm64/include/asm/preempt.h:11-14` |
| arm32 | `READ_ONCE(current_thread_info()->preempt_count)` — **per-task** (no `arch/arm/include/asm/preempt.h`; falls through to asm-generic) | `include/asm-generic/preempt.h:9-12` |

On Arm a task reads its own count, not the processor's. An intruder on a
processor whose idle task holds a bottom-half-disabled bracket reads **zero**.
The argument establishes nothing there.

**2. Where `CONFIG_PREEMPT_COUNT` is unset, a raised count is not what stops
scheduling.** `include/linux/preempt.h:295` is literally `#define preemptible()
0`, and `CONFIG_PREEMPTION` selects `CONFIG_PREEMPT_COUNT`
(`kernel/Kconfig.preempt:92-94`), so `!PREEMPT_COUNT` implies a non-preemptible
kernel. Nothing consults the count for preemption decisions.

The comment now names the mechanism that actually holds, which is
`may_use_simd()` on four operating environments and the preemption model on the
fifth.

### 13.4.6 arm32 is the one exception, and PREEMPTION=0 is its guarantee

K4 builds against `linux-6.6.99-arm`, whose `include/generated/autoconf.h` has
`CONFIG_PREEMPT_NONE=1`, `CONFIG_PREEMPTION` unset, `CONFIG_PREEMPT_COUNT` unset,
`CONFIG_SMP=1`. There is no involuntary preemption at all, which is what keeps
another task off the processor mid-bracket. The module's `migrate_disable()`
(compiled there: SMP, `!PREEMPT_COUNT`, 6.6 >= 5.7; a real `extern` under
`CONFIG_SMP` per `include/linux/preempt.h:426`) pins the holder, but pinning the
holder is not the same statement as excluding an intruder.

**Record this as the standing answer:** on arm32 the premise rests on the
operating environment kernel's preemption model, not on `preempt_count` and not
on `may_use_simd()`. Anyone re-deriving this should start from that kernel's
`autoconf.h`.

### 13.4.7 How the arbitration is kept out of a certified module

**Two independent controls, in that order.**

1. **The certified build compiles a different implementation.** The minimal arm
   at the head of this section is what v5, v6, v7 and FIPS Ready build. None of
   the arbitration code is in the translation unit at all, so there is nothing to
   switch off.
2. **Within the arbitration arm, the reclaim is off by default under FIPS.**
   `WC_LINUXKM_SVR_NO_SLOT_RECLAIM` compiles out the three arms; an occupied slot
   belonging to another `(pid, ctx)` is refused and the caller receives an error.
   The guard encloses the `find_get_pid()` call as well as the arms — disabling
   only the arms would leave that reference unreleased. Defining
   `WC_LINUXKM_SVR_SLOT_RECLAIM` restores the old behaviour.

Control 2 is what a development flavour gets, and it is why the measurements
below were taken. Control 1 is what makes the question moot for a submission.

**Retained in both arms:** the depth counter, which is documented-correct
(13.4.1a) and is the whole of what the certified arm implements. The cross-CPU
slot scan of section 13.3 lives in the arbitration arm only; it is upstream's
code and keeps its own recommendation there.

### 13.4.8 The arbitration arm with the reclaim off, measured

Re-run of the same harness with the arms compiled out, controls held,
`verify rc=0`. This measures control 2 above, on the arm that still has a slot
table to plant into:

| planted in the processor's slot | reclaim compiled out |
| :--- | :--- |
| idle task, claimed just now | REFUSED |
| idle task, claimed 6 s ago | REFUSED |
| a real leak (FPU section left open) | REFUSED |
| a process that has exited | REFUSED |
| *control:* a live nonzero pid | REFUSED |
| *control:* our own pid | **TAKEN** |

The last row is the one that makes the rest meaningful: our own slot is still
found, used and released, so the stimulus provably reaches the slot code. Every
form of "someone else's slot" is refused, and the module emitted **zero** reclaim
log lines against 40 for the same arms before the change.

**Functional evidence from the same boot:** the module loads and **43 algorithms
self-test OK and register**, each of which runs through the save/restore bracket.
No kernel splat on a `PROVE_LOCKING` kernel.

**Note for whoever runs this next:** the harness positive control was changed for
this. It used to be "plant an exited pid, it must be reclaimed", which asserts the
behaviour that is now compiled out and therefore voids a healthy run. The control
is now "plant our own pid", which never goes through a reclaim arm and is valid
either way.

### 13.4.9 What is not established

**These are open questions about the arbitration arm — development flavours and
non-FIPS builds. None of them bears on a certified module, which has no slot
table.** They are listed because the arm is still in the tree and someone will
eventually decide whether to delete it outright.

1. **arm32 is unmeasured, and it is the case most likely to differ.** Every
   result in 13.4.3 is x86_64. The x86 conclusion rests on `may_use_simd()`
   refusing upstream via a per-CPU flag; arm32 has no such flag. The reclaim may
   therefore be reachable on arm32 where it is not on x86. The run is written and
   gets as far as a grafted arm32 module and two completed boots, then insmod
   fails on `linuxkm_lkcapi_register() ... -22`, which is a separate pre-existing
   defect in a configuration the operating-environment matrix has never built.
2. **Nobody has produced a leaked slot.** The harness plants the state; it does
   not demonstrate the state arising on its own. The only route found is a save
   with no matching restore, which also leaks the FPU section and is therefore
   not repairable by any slot reclaim.
3. **No worst-case bracket duration has been measured**, on any architecture.
4. **The refusal behaviour has not been soak-tested.** With the arms disabled, a
   slot that does leak takes that processor out of accelerated crypto for the
   life of the module. Callers get errors rather than wrong answers, but the
   failure is permanent and processor-wide, and no long-running test has been run
   in this configuration.
5. **`may_use_simd()` as a staleness oracle was considered and withdrawn.** It
   would replace a clock with the kernel's own per-CPU state, which is sound
   reasoning on x86 and arm64, but the function is not part of the documented
   module-facing interface and is nearly empty on arm32. Building policy on it
   repeats the original mistake in a new place.
6. **A wrong reclaim has two outcomes, not one**, depending on which party
   restores first. Both are derived from control flow; neither has been
   reproduced.
   * *intruder first* — it releases the slot, the idle task then finds the slot
     free, falls past the "belongs to another pid" guard in
     `wc_restore_vector_registers_x86()` and does unwind. Accounting comes out
     balanced; one preemption level leaks and `schedule_debug()` resets it with a
     `__schedule_bug()` splat.
   * *idle task first* — the guard fires, prints "releasing nothing" and returns.
     `wc_svr_bracket_depth` for that processor stays above zero for the life of
     the module, and `wc_LockMutex()` returns `BAD_STATE_E` there permanently
     (`linuxkm/module_hooks.c`, the `wc_linuxkm_in_svr_bracket()` refusal), DRBG
     included.

   In both orderings the vector registers were already clobbered before the slot
   code ran, because `kernel_fpu_begin()` / `kernel_neon_begin()` is called
   first. **The slot bookkeeping is downstream of the damage, not the cause of
   it.**
7. `in_kernel_fpu` is a bool, not a depth count (`DEFINE_PER_CPU(bool,
   in_kernel_fpu)` at `arch/x86/kernel/fpu/core.c:47`, set at `:428`, cleared at
   `:450`, read by `irq_fpu_usable()` at `:64`). So an **unpaired** begin leaves
   it set and every later save on that processor returns `WC_ACCEL_INHIBIT_E`;
   but **two begins followed by one end clear it.** Any claim that an imbalance
   permanently disables the processor for crypto is wrong.

### 13.4.10 What makes these conditions defects

Several comments in `x86_vector_register_glue.c` argued that a failure was severe
*because* there is one implementation per algorithm and no C fallback to absorb
it. That is an argument for reinstating the fallback, and it is not the reason
any of these conditions matter. Under the elected posture a single implementation
returning an error to its caller is the design behaving correctly. **What makes
these conditions defects is that they are permanent and processor-wide**, not
that no second implementation catches them. Do not reintroduce the other
framing.

### 13.4.11 No validated operating environment is `CONFIG_PREEMPT_RT`

Read from each tree's `include/generated/autoconf.h`:

| tree | used by | `PREEMPT_RT` | `PREEMPT_COUNT` | `PREEMPTION` |
| :--- | :--- | :--- | :--- | :--- |
| `linux-6.6.99` | K2, K3, and K1 via `k1-i386/linux-6.6.99` | 0 | 1 | 1 |
| `linux-6.6.99-arm64` | K5 | 0 | 1 | 1 |
| `linux-6.6.99-arm` | K4 | 0 | **0** | **0** |
| `linux-6.12.59-rt` | nothing; compile-only tree | **1** | 1 | 1 |

`matrix/oes.manifest` lists U1-U7 and K1-K5; there is no RT cell. Every
`#if IS_ENABLED(CONFIG_PREEMPT_RT)` arm in this file is dead text in all twelve.

**Gate, with its negative control.** A probe compiling
`#if IS_ENABLED(CONFIG_PREEMPT_RT)` against each tree's `autoconf.h` reports the
RT arm live **only** for `linux-6.12.59-rt`, and independently reports
`PREEMPT_COUNT` off for `linux-6.6.99-arm` and on elsewhere. It therefore
distinguishes both conditions it is asked about rather than returning a constant.

---

## 13.5 `sp_x86_64.c` — unbracketed AVX2 in ECC, and where the vector registers actually are

This is the third instance of the section 13.3 shape, with the sign reversed: the
earlier two were scaffolding the kernel does not sanction; this one was a
guarantee the kernel *requires* that had been removed.

### 13.5.1 What the kernel requires, in its own words

Four statements, all from kernel documentation, none from commentary in this
tree:

1. Kernel code is "normally prohibited from using floating-point (FP) registers
   or instructions." Use is the exception, permitted by "isolating the functions
   containing FP code to a separate translation unit ... and **saving/restoring
   the FP register state**."
2. "It is only valid to call `kernel_fpu_begin()` after a previous call to
   `kernel_fpu_available()` returned `true`."
3. "**Preemption may be disabled inside critical sections, so their size should
   be minimized.**"
4. "These functions are only guaranteed to be callable from (preemptible or
   non-preemptible) **process context**."

   — Documentation/core-api/floating-point.rst,
   https://docs.kernel.org/core-api/floating-point.html

The consequence of omitting the bracket is not stated on that page but is the x86
FPU maintainers' settled position: FPU/SIMD registers are not preserved across
kernel preemption, so kernel SIMD outside a bracket **silently corrupts userspace
FPU state**. The commit that made `kernel_fpu_begin/end()` mandatory rejects
hand-rolled save/restore for three reasons, the third being "corrupting the
extended state of those vector registers."

   — *x86, fpu: always use kernel_fpu_begin/end() for in-kernel FPU usage*,
   https://lkml.iu.edu/hypermail/linux/kernel/1208.3/00450.html

Rule 3 has a documented mechanism for bulk ciphers that public-key code does not
get for free:

> "the crypto subsystem operates on memory pages and requires users to 'walk and
> map' these pages while processing a request. This operation must occur outside
> the `kernel_fpu_begin()`/`kernel_fpu_end()` section because it requires
> preemption to be enabled. These preemption points are generally sufficient to
> avoid excessive scheduling latency."
>
> — Documentation/core-api/real-time/architecture-porting.html

The kernel's own AES-NI driver shows the pattern: it re-brackets per walk segment
rather than holding one section across a request
(`arch/x86/crypto/aesni-intel_glue.c`). A scalar multiply has no data walk and
therefore no natural yield point, which is why the section length here had to be
addressed deliberately rather than inherited.

### 13.5.2 Where the vector registers actually are

The routine names are misleading. "avx2" in an SP symbol denotes the
BMI2/ADX/AVX2 *dispatch lane*, not that the routine uses vector registers. Census
of `sp_x86_64_asm.S`, counting `%xmm`/`%ymm` operands per routine:

| | routines | vector-register users |
| :--- | ---: | ---: |
| avx2-named asm routines | 79 | **23** |
| pure BMI2/ADX integer, no vector registers | | **56** |

The 56 include all the heavy field arithmetic — `mont_mul`, `mont_sqr`, `mul`,
`sqr`, `mont_reduce_order`, `cond_sub`, `mont_div2`. These need no bracket at
all. `sp/mont.rb` already said so ("only uses BMI2 and ADX, no AVX2, so no
`ASSERT_SAVED_VECTOR_REGISTERS()`"), and the census confirms it.

The 23 split into two kinds:

- **Algorithmic** — constant-time table selection: `sp_*_get_entry_64/65_*`,
  `sp_*_get_point_33_*`, `sp_*_get_from_table_*`, and `sp_256_mod_inv_avx2_4`.
  These use `vpermd`/`vpcmpeqd`/`pand`/`por` to select a point or window entry
  without branching. Genuinely vector work; a bracket is mandatory. Densest
  example: `sp_2048_get_from_table_avx2_32`, 1815 vector of 2010 instructions.
- **Incidental** — `xmm0` used as a 128-bit block-copy register in an otherwise
  integer routine, e.g. `sp_2048_mul_avx2_16` at 16 vector of 1396 instructions,
  the whole of it `vmovdqu (%rbx),%xmm0` / `vmovups %xmm0,(%rdi)` pairs in the
  epilogue. Not arithmetic; a wide `mov`.

That distinction drives the fix. A bracket is owed wherever a vector register is
touched — the kernel draws no line between "arithmetic" and "memcpy" use, and
`xmm0` is caller-saved by the SysV ABI but *not* saved by the kernel across
preemption. So incidental use is worth eliminating rather than bracketing.

### 13.5.3 What was wrong

The commit that removed the run-time fallback from certified FIPS builds
converted the dispatch from

```c
if (... IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
    err = sp_256_ecc_mulmod_avx2_4(...);
    RESTORE_VECTOR_REGISTERS();
}
else
    err = sp_256_ecc_mulmod_4(...);       /* different implementation */
```

to a CPUID-only test. Removing the fallback was correct: selecting a *different
implementation* because the bracket failed is run-time implementation selection.
But `SAVE_VECTOR_REGISTERS2()` was doing two jobs in that expression — choosing
the lane *and* taking the bracket — and the conversion removed both. It added 172
bracket lines elsewhere and missed the ECC mulmod sites.

The result, in a default build (`--enable-fpecc` defaults to no):

```
sp_ecc_mulmod_256                  no bracket
  -> sp_256_ecc_mulmod_avx2_4
       #ifndef FP_ECC   -> tail-call, no bracket   <-- default arm
       #else            -> SAVE_VECTOR_REGISTERS2()  (cache arm only)
  -> sp_256_ecc_mulmod_win_add_sub_avx2_4     0 brackets
       -> sp_256_get_point_33_avx2_4
            vpermd %ymm7, %ymm8, %ymm7        sp_x86_64_asm.S:45561
```

Same shape at 256 / 384 / 521 / 1024.

**A comment made this hard to see, and misled two review passes.** The generator
said the accelerated lane "runs under `SAVE_VECTOR_REGISTERS()`. Take it HERE,
inside the point-cache lock" — true of the `#else` arm, which has the cache, and
false of the default arm, which has neither cache nor bracket. Read at face value
it says the callee always brackets, so every caller looks covered. The comment in
`sp/ecc_mul.rb` now distinguishes the two arms.

### 13.5.4 Reproduction, before any fix

`ASSERT_SAVED_VECTOR_REGISTERS()` prints when `wc_svr_count <= 0`. Built
`--enable-fips=v7 --enable-intelasm --enable-sp --enable-sp-asm` with
`-DDEBUG_VECTOR_REGISTER_ACCESS`, then one `testwolfcrypt` run:

```
ASSERT_SAVED_VECTOR_REGISTERS : sp_384_mont_sqr_avx2_6() sp_x86_64.c @ L 28798
  : wc_svr_count 0 (last op sp_x86_64.c L 49624)

127,697 assert failures        testwolfcrypt exit 0
```

**Control: 2 of 25 assert sites fired.** Twenty-three correctly-bracketed sites
stayed silent, so the instrumentation works and the finding is specific. Note
`testwolfcrypt` still exits 0 — the assert only prints — which is why this
survived normal test runs.

Only P-384 and P-1024 report, because the assert needs a C body to live in:
`sp_384_mont_mul_avx2_6` is a C wrapper over asm primitives, while
`sp_256_mont_mul_avx2_4` is `extern`, implemented wholly in `.S`. **The silence of
P-256 and P-521 is a property of code shape, not evidence that they are safe** —
they run the same unbracketed AVX2 with nothing watching. Adding asserts there is
impossible, not merely redundant.

### 13.5.5 Why the section length was reduced rather than just bracketed

Measured on a Core Ultra 9 285K, one bracket per operation:

| operation | cycles/op | section held |
| :--- | ---: | ---: |
| ECDHE P-256 agree | 96,121 | 26 us |
| RSA-2048 private | 1,108,328 | 301 us |

301 us with preemption *and* softirqs disabled, to protect 16 `xmm0` block-copy
instructions buried in 1396 integer ones. That is the rule-3 problem in one line,
and the kernel's bulk-cipher preemption points do not apply here.

The cost of the alternative was measured rather than assumed. A kernel module
timing `kernel_fpu_begin()`/`kernel_fpu_end()` pairs, run in a throwaway VM on
the matching 6.17.0-1030-oem kernel under KVM with AVX2 present:

```
fputime: iters=200000 empty=160844 cyc bracketed=5072712 cyc
fputime: RESULT 24 cycles per kernel_fpu_begin+end pair
```

At 24 cycles, bracketing the table lookups per call — roughly 43 per P-256 scalar
multiply, roughly 400 per RSA-2048 modexp — costs **1.07%** and **0.87%**
respectively. Sub-1% to remove a 301 us non-preemptible section is not a close
trade.

Caveat: in a tight loop the first `kernel_fpu_begin()` saves the task FPU state
and the rest skip it while `TIF_NEED_FPU_LOAD` stays set, so 24 cycles is the
correct *marginal* cost for repeated brackets within one operation, and would
understate brackets spread across separate operations. One processor model.

### 13.5.6 The fix

Both changes are in the generator (`kh-fork-scripts`), not the generated files.
Reference gate first, per the standing rule: `ruby sp.rb x86_64 sp_x86_64_asm
sp_x86_64.c` reproduced both checked-in files **byte-identically** before any
edit, and after the edits the regenerated diff contains only the two intended
changes.

**A. Remove the incidental vector use** (`sp/x86_64/maths.rb`, 2 sites). The
epilogue block copy emits integer moves instead of `vmovdqu`/`vmovups` on `xmm0`;
the generator already used that form for the odd-word tail. Effect: vector
instructions in `mul`/`sqr` routines **86 → 0**. Those routines no longer oblige
any caller to hold a bracket.

**B. Bracket the accelerated lane once, in the callee** (`sp/ecc_mul.rb`, 1 site).
The `#ifndef FP_ECC` arm now takes the bracket directly around the window call.
This covers **all nine** AVX2 dispatch sites in `sp/ecc.rb` at once. Four of those
were genuinely unbracketed (`sp_ecc_mulmod_*`, `sp_ecc_mulmod_add_*`,
`sp_ecc_secret_gen_*`, `sp_ecc_check_key_*`) and five already sat inside an outer
save, so patching call sites individually would have been four separate edits
each needing its own liveness analysis, with double-bracketing risk.

Bracketing in the callee also respects the lock ordering the generator already
documents: the `#else` (FP_ECC) arm must take the point-cache lock *before* the
bracket, because a `wolfSSL_Mutex` is `spin_lock_bh()` and sleeping locks cannot
nest inside spinning ones (Documentation/locking/locktypes.rst). That arm is
untouched. The non-AVX2 lane is C and emits no bracket.

### 13.5.7 Result

```
assert failures   127,697  ->  0          testwolfcrypt exit 0
SVR2 sites in .c       99  ->  103        (one per curve)
vector insns in mul/sqr 86  ->  0
```

Throughput, 3 runs each, against the *broken* baseline:

| | baseline (broken) | A only | A+B fixed | vs baseline |
| :--- | ---: | ---: | ---: | ---: |
| RSA-2048 private | 3276.9 | 3338.0 | 3376.6 | **+3.04%** |
| ECDHE P-256 agree | 39047.6 | 39266.4 | 39661.6 | **+1.57%** |

The corrected build is faster than the one that skipped the bracket. RSA's gain is
above the ~1.2% run-to-run spread; ECDH's is at its edge. Plausibly the removal
of SSE/AVX transition effects in the copy loops. **The defensible claim is the
weaker one: correctness cost nothing measurable.**

### 13.5.8 The Arm SP generators cannot carry this defect

The `#ifndef FP_ECC` shape does exist there — `sp/ecc_mul.rb` is shared and
requires `arm32/ecc_mul.rb` and `arm64/ecc_mul.rb` — but the code inside it is
integer-only, so there is nothing a missing bracket could expose. Read three
independent ways from `sp_arm64.c`, `sp_arm32.c`, `sp_armthumb.c` and
`sp_cortexm.c`:

* **Clobber lists.** Every `__asm__` block across the four files declares only
  `r`/`x`/`w` registers. **Zero** `v`/`q`/`d`/`s` clobbers.
* **Instruction vocabulary.** The four files use 84 distinct mnemonics between
  them and every one is integer, branch or load/store. No NEON, no VFP, no crypto
  extensions — no `v*` mnemonic at all, no `ld1`/`st1`/`movi`/`fmov`.
* **Bracket count.** **0** real `SAVE_VECTOR_REGISTERS` call sites in all four
  files, against **205** in `sp_x86_64.c`. The only mentions are a block that
  `#define`s the macros to their `SAVE_NO_VECTOR_REGISTERS` forms.

All four regenerate byte-identically from `sp/sp.rb` (targets `ARM64`, `ARM32`,
`Thumb2`, `ARM_Thumb`), so the checked-in files are what the generators produce.

**Scope boundary:** this is about the SP generators only. Arm SIMD crypto does
exist elsewhere in the tree — `port/arm/armv8-aes-asm.S`, `armv8-mlkem-asm.S`,
`armv8-sha3-asm.S` and others are heavy vector code. That question is 13.5.9.

### 13.5.9 aarch64 NEON crypto was unbracketed

**The issue.** The aarch64 SHA-256, SHA-512 and AES lanes executed NEON code
without taking the kernel's save/restore bracket at all.

**The fix.** Brackets added to those lanes, in the same fail-closed form the rest
of the module uses (`if (_svr != 0) return _svr;`). Bracket counts in the
preprocessed kernel-module sources, x86_64 alongside aarch64:

| file | x86_64 | aarch64 before | aarch64 after |
|---|---:|---:|---:|
| sha256 | 2 | 0 | **2** |
| sha512 | 2 | 0 | **2** |
| aes | 30 | 0 | **2** |
| sha3 | 6 | 4 | 4 |

**x86 regression gate, run after each commit:** the preprocessed x86 token stream
(line markers stripped) is byte-identical, the x86 bracket counts are unchanged
at 2/2/30/6, the x86 object disassembly of all four files is identical, and the
whole x86 module `.text` hashes the same as a pristine pre-change build. Intel
AES-NI is untouched, not merely unaffected.

**Runtime result on arm64 — no regression.** The fixed module and a pristine
pre-change module were each built for K5, in-core hash updated, and booted under
`qemu-system-aarch64 -M virt -cpu max` on Linux 6.6.99-arm64 with the K5
initramfs. Both reach `FIPS 140-3 wolfCrypt-fips v7.0.0 startup self-test
succeeded`:

| | pristine | with brackets |
|---|---:|---:|
| power-on self-test | succeeded | succeeded |
| algorithm self-tests OK | 42 | 42 |
| self-test failures | 2 | 2 |
| algorithms registered | 42 | 42 |

**Behaviourally identical** — the brackets cost nothing observable and break
nothing.

**The brackets are load-bearing, proven by A/B under an inhibited save.** Two K5
arm64 modules built identically except for the brackets, both with
`EXTRA_CFLAGS=-DDEBUG_VECTOR_REGISTER_ACCESS_ALWAYS_OFF`, which makes
`SAVE_VECTOR_REGISTERS2()` return `WC_ACCEL_INHIBIT_E` unconditionally:

| arm | result on insmod |
|---|---|
| **with brackets** | `HMAC Known Answer Test check FIPS error`, `-206`, **module in DEGRADED mode** |
| **without brackets** | `startup self-test succeeded`, **43 algorithms registered** |

The bracketed module refuses service the moment the vector registers are denied —
the SHA bracket returns the inhibit error, the HMAC KAT fails, and the module
degrades rather than compute with registers it does not own. The unbracketed
module does not notice the denial at all and executes the NEON code regardless,
which is precisely the exposure this section closes. The contrast is the proof
that the brackets execute on the live path, not merely that they compile.

**How to detect this, and how not to.** The bracket is invoked **indirectly**
through the PIE redirect table, in two different accessor forms —
`wolfssl_linuxkm_pie_redirect_table.wc_save_vector_registers_x86` on x86_64 and
`wolfssl_linuxkm_get_pie_redirect_table_local()->...` on aarch64. Counting
`bl <symbol>` in the linked module therefore returns 0 on **both** architectures
and proves nothing; an x86_64 module known to bracket scores the same 0 as an
unbracketed aarch64 one. **Any future check here must be shown to fire on a
known-bracketed path before its silence is read as evidence.**

**ML-KEM needed no change.** `WOLFSSL_AARCH64_NO_SQRDMLSH` is defined in this
build and all three `MLKEM_LANE_ARM_RDM()` sites sit under
`#ifndef WOLFSSL_AARCH64_NO_SQRDMLSH`, so the aarch64 vector lane is not
compiled. Bracketing it would have been bracketing dead code.

**`AES_ECB_encrypt` / `AES_ECB_decrypt` need no bracket.** They are the else-arm
of the aarch64 AES dispatch and were initially mistaken for thunks. Measured over
their full extent: 303 and 277 instructions, **zero** vector operands, no
`d8`-`d15` saves, no outbound calls — integer T-table AES, leaf functions. The
vector arm is `AES_{en,de}crypt_AARCH64` at 41 instructions and 37 vector
operands, which is what the fix brackets.

### 13.5.10 AES-XTS decrypt used the encryption key schedule on aarch64

Pre-existing and unrelated to the bracket work; surfaced by the runtime trace
above.

**The defect.** `wc_AesXtsDecrypt()` resolves the correct AES context once, at the
top:

```c
#ifdef WC_AES_XTS_SUPPORT_SIMULTANEOUS_ENC_AND_DEC_KEYS
    aes = &xaes->aes_decrypt;
#else
    aes = &xaes->aes;
#endif
```

Every x86 lane (`_aesni`, `_avx1`, `_vaes`, `_avx512`) and the RISC-V lane pass
`aes->key`. The **Arm and PPC64 lanes passed `xaes->aes.key` directly**, bypassing
that resolution — `AES_XTS_decrypt_AARCH64`, `_NEON`, the Arm base lane and the
PPC64 lane, plus their `tmp` and `rounds` arguments.

**Why it only bites in the kernel.** `xaes->aes` and `xaes->aes_decrypt` are the
same object unless `WC_AES_XTS_SUPPORT_SIMULTANEOUS_ENC_AND_DEC_KEYS` is defined,
and `linuxkm/linuxkm_wc_port.h` defines it unconditionally under
`LINUXKM_LKCAPI_REGISTER`. With it set, `wc_AesXtsSetKeyNoInit(AES_DECRYPTION)`
builds the decryption schedule into `aes_decrypt` and leaves `aes` holding the
**encryption** schedule — so the Arm lanes decrypted with the wrong key schedule
and every output byte was wrong.

**Proof.** The kernel's wrong plaintext is byte-identical to a userspace decrypt
deliberately run against the encryption schedule:

```
kernel got_buf        f18b4d9867268d797b7525b105908102c4d4913149215ce3
enc-schedule decrypt  f18b4d9867268d797b7525b105908102c4d4913149215ce3
expected plaintext    ebabce95b14d3c8d6fb350390790311c6e4b92013e768ad5
```

and one build flag reproduces it standalone on aarch64 userspace —
`EXTRA_CFLAGS=-DWC_AES_XTS_SUPPORT_SIMULTANEOUS_ENC_AND_DEC_KEYS` with
`--enable-armasm` fails; without it passes. Reproducer: `xts-repro.c`.

**The fix.** The Arm and PPC64 lanes now receive `(byte*)aes->key`, matching the
resolution at the top of the function. The arm32 dispatch also selected its lane
on `xaes->aes.use_aes_hw_crypto` while executing against `aes`; both flags come
from one CPUID read so they agree and no failure was observed, but reading one
context and running another is the exact anti-pattern that produced this bug, so
it now reads `aes->use_aes_hw_crypto`.

**Result.** The standalone reproducer flips MISMATCH → MATCH. On the K5 arm64
kernel: `xts-aes` self-tests OK and registers, **43 algorithms instead of 42**,
and a `-22` registration failure is gone. x86_64 regression gate: `aes.o`,
`sha256.o`, `sha512.o`, `sha3.o` disassemble identically to a pristine build and
the whole x86 module `.text` hashes unchanged — the change is inside
`__aarch64__` / arm32 / PPC64 arms that x86 never compiles.

**Streaming path audited, and it is clean — and note this is compile-time
selection, not run-time fallback.** `wc_AesXtsDecryptUpdate()` carries one
accelerated block, `#if defined(WOLFSSL_AESNI)`, whose lanes already use
`aes->key`. On Arm that block is preprocessed away entirely: the K5 arm64 build
contains **zero** occurrences of `AES_XTS_decrypt_update_{aesni,avx1,vaes,
avx512}` and zero of `use_aesni` — the branch symbol itself is absent, so there is
no run-time choice to make and `AesXtsDecryptUpdate_sw()` is the only
implementation compiled. It resolves `&xaes->aes_decrypt` correctly, so the
one-shot decrypt was the only defective path.

Where that branch **does** compile (x86_64) it is the shape section 3.0 requires,
not the fallback that was removed:

```c
if (aes->use_aesni) {                         /* CPU capability -- stepping */
    SAVE_VECTOR_REGISTERS(return _svr_ret;);  /* save failure ENDS the call */
    ...accelerated...
    RESTORE_VECTOR_REGISTERS();
}
else                                          /* only on a part without AES-NI */
{ ret = AesXtsDecryptUpdate_sw(...); }
```

The `else` arm is reached when the processor lacks AES-NI, never when the
vector-register save fails — that path returns `_svr_ret`.
`scripts/fips-no-svr-fallback-check.sh` reports 0 sites for both shapes over this
file, on both architectures.

**arm32 builds this combination.** `wolfcrypt/src/cpuid.c` auto-defines
`WOLFSSL_ARM32_PRIVILEGE_MODE` under `WOLFSSL_LINUXKM` and reads `ID_ISAR5`
directly, so the userspace-only `getauxval()` / `<sys/auxv.h>` branch is never
compiled in kernel space. Verified by building the K4 line —
`--enable-linuxkm --enable-fips=v7 --enable-armasm --enable-sp-asm
--host=arm-linux-gnueabihf --with-linux-arch=arm` against linux-6.6.99-arm —
which produces a 3,027,388-byte `libwolfssl.ko` with **zero** `getauxval`
imports, matching the operating-environment matrix, which records K4 arm32 kernel
green. In that build `AES_XTS_decrypt_AARCH32` is compiled and receives
`aes->key`, so the fix is active on arm32 as well as aarch64. The
`use_aes_hw_crypto` line sits under `WOLFSSL_ARM32_AES_DISPATCH`, which this
configuration does not enable (0 references survive preprocessing), so that one
edit is compiled out here and remains unexercised — unexercised, not
uncompilable.

**This is not over-architecture.** Unlike the fallback and the ownership
arbitration, the second key slot answers a real external contract: the Linux
skcipher API keeps expanded encrypt and decrypt keys loaded simultaneously per
transform, and the in-tree implementations carry two AES key structs for exactly
that. `WC_AES_XTS_SUPPORT_SIMULTANEOUS_ENC_AND_DEC_KEYS` is an upstream wolfCrypt
option, and setting it avoids duplicating the tweak key. The defect was an
**incomplete port** of that option — x86 and RISC-V lanes were updated to read
the resolved context, the Arm and PPC lanes were not — in a configuration
(armasm + linuxkm) nothing routinely exercises.

---

## 13.6 The in-core integrity hash now covers ARM relocation targets

ISO/IEC 19790:2012 §7.10.2 requires the pre-operational software integrity test
to cover the module's executable code. On ARM and AArch64 it did not cover the
target of any relocated branch or data reference.

### 13.6.1 What was wrong

`wc_reloc_normalize_segment()` (`linuxkm/linuxkm_memory.c`) canonicalises
relocated fields so the digest is reproducible across load addresses. x86
normalized by **computing** a load-address-independent value; ARM and AArch64
normalized by **erasing** the field:

```c
case WC_R_AARCH64_CALL26:   /* and 20 others */
    /* Don't attempt to reconstruct ARM destination addresses -- just
     * normalize to zero. ... but it's very fidgety. */
    reloc_buf = 0;
```

The write-back stored the whole word, so the instruction opcode was discarded
along with the target. The comment recorded this as a necessity. It was not one:
x86 achieves a stable hash without discarding anything, in the same function.

Worse, most ARM branch relocations are **PC-relative**, so their encoded value is
already load-address-invariant. Erasing them bought no stability at all.

### 13.6.2 The fix

All ARM and AArch64 relocations now take the same normalization x86 takes,
yielding the same canonical value: the target's offset within its destination
segment. Three additions ARM requires:

* **mask-based gather/scatter** — ARM scatters some immediates across
  non-contiguous instruction bits (`ADR_PREL_PG_HI21` splits a 21-bit page
  offset across bits 30:29 and 23:5), so fields are extracted and reinserted
  under `layout->mask` rather than by shifting.
* **scaling** — branch displacements are word-scaled, `ADRP` is page-scaled, and
  the `LDST*_ABS_LO12_NC` immediates are scaled by access size. Relative fields
  are unscaled to bytes for the arithmetic; absolute fields stay in their own
  units and the segment base is scaled to match.
* **opcode preservation** — bits outside the mask are carried through, so the
  instruction itself stays in the digest.

### 13.6.3 Verification

Two properties are in tension and both are required: **stability** (the same
module at two load addresses must hash identically) and **coverage** (two
different relocation targets must hash differently). A harness drives the real
`wc_reloc_normalize_segment()` on the runtime path (`text_is_live = 1`, as
`module_hooks.c` sets it):

| relocation | stable | covers |
| :--- | :--- | :--- |
| `R_X86_64_PC32` *(control)* | yes | yes |
| `R_AARCH64_CALL26` | yes | yes |
| `R_AARCH64_JUMP26` | yes | yes |
| `R_AARCH64_ABS32` | yes | yes |
| `R_AARCH64_ADR_PREL_PG_HI21` | yes | yes |
| `R_AARCH64_ADD_ABS_LO12_NC` | yes | yes |
| `R_AARCH64_LDST64_ABS_LO12_NC` | yes | yes |
| `R_ARM_CALL` | yes | yes |
| `R_ARM_ABS32` | yes | yes |

Before the fix, every ARM row read `stable / blind`. With the erasure removed but
no reconstruction, the absolute rows read `unstable / covers` — which is what
makes the zeroing look necessary if you stop there.

x86_64 normalized output is byte-identical to its pre-change baseline; the x86
case labels are untouched. The module builds clean and the in-core hash step
reports `Relocation table is stable.`

---

## 14. Limitations — where the wording is stronger than the evidence

Held to the same standard as the rest of the document.

1. **The failure measurements are not yet on disk.** 62,915 / 29.7 s / 28.9 s /
   61,458 and 0/2 → 2/2 come from the session that found the defect. A harness is
   being built to capture them durably under `matrix/source-of-truth-runs/`.
   **Until it lands these are reported results, not filed artifacts** — do not
   put them in a submission. The verification kernel exists and is configured as
   stated.

2. **The section 12.1 performance numbers cover one of the four kernel operating
   environments.** Only 64-bit x86_64 was measured. The other three benchmark
   cells exist and were run; all three failed with a stated reason, and none of
   them is a "not applicable":
   * `32-bit-arm-kernel-…` — the PAA build does not compile.
     `wolfcrypt/src/cpuid.c` includes the userspace `<sys/auxv.h>` and calls
     `getauxval()` on the 32-bit Arm path with no `WOLFSSL_LINUXKM` guard
     (upstream PR #11031); `--enable-armasm` is what supplies PAA there, so there
     is no PAA build to time. The cell probes the guard rather than citing the
     pull request, and the probe is negative-tested both ways.
   * `64-bit-arm-kernel-…` — builds, but this host is x86_64, so an aarch64 guest
     runs QEMU TCG and every AES/SHA instruction is interpreted. A difference
     measured there would describe QEMU, not the operating environment's silicon.
     Needs real aarch64 hardware.
   * `32-bit-x86-kernel-…` — the configure-time lane selection arm B used had no
     i686 case at all (it keyed on `*x86_64*|*amd64*` and `*aarch64*`), so there
     is no second side to the comparison; and K1's PAA module has not loaded
     (non-PIC relocations → `-203`), so nothing reaches the benchmark autorun
     anyway.

   **Do not generalise section 12.1 to Arm.** The AES and SHA-256 lane defects
   are x86-specific findings; whether aarch64 CPUID selection reaches its part's
   best lane is untested.

3. **Arm A needed one edit to compile at all**, disclosed rather than folded in
   silently: `wolfcrypt/src/random.c` guards two `devId` writes on
   `WOLFSSL_SMALL_STACK_CACHE` alone, while the member exists only under
   `WOLF_CRYPTO_CB`, so the kernel FIPS configuration does not build. The guard
   was corrected to `defined(WOLFSSL_SMALL_STACK_CACHE) &&
   defined(WOLF_CRYPTO_CB)` — which is exactly what arm B already carries.
   `WOLF_CRYPTO_CB` is undefined in this build, so the guarded write compiles to
   nothing in **both** arms and the generated code is unaffected. It is a
   pre-existing build break on the fallback branch, not something the benchmark
   introduced.

4. **The B2 arm is a diagnostic, not a proposal.** It shows the deficit is lane
   selection rather than the one-implementation rule. It does not establish that
   `VAES_AVX2` / `AVX1_SHA` / SLH-DSA `AVX2` are the right lanes to ship: each
   would need its own CAST and operating-environment claim, and the SHA-NI stall
   in section 12.1.3 is an open objection to `AVX1_SHA` specifically.

5. **"No validated kernel operating environment enables the LKCAPI
   registration"** comes from the operating-environment build records, not a
   rebuild for this document. Re-confirm before submission use.

6. **Kernel sources are Linux 6.12.59**, `crypto/drbg.c` spot-checked against
   6.6.99, and the migration and slot arguments derived from 6.6.99 and 6.1.62.
   Check a target kernel against its own tree before repeating a claim for that
   operating environment. Section 12.8 states which sections cite which version.

7. **Upstream's direction of travel was not verified here.** An earlier account
   described Linux moving to unconditional SIMD after a 6.15 nesting fix and
   later deleting `crypto/simd.c`. No 6.15+ tree was available, so those commits
   and their benchmark figures are **not** relied on anywhere in this document.

8. **Section 7's third bullet** says an arm "hashes nothing" in one build shape.
   That it does nothing is read from source; whether it is reachable was not
   determined — which is the point about the annotation. Do not restate it as
   "there is a live bug there."

9. **Section 5.2 describes the bank; it does not endorse it.**

10. **Section 11.5's error-state concern is not adjudicated.** The `-209`
    continuous-test path to `FIPS_MODE_FAILED` is intact and verified in
    `fips.c`. What is unresolved is whether any self-test failure reaches the
    `RNG_FAILURE_E` retry rather than being intercepted first. Nobody has taken
    this to the laboratory. Do not cite it as a confirmed violation — cite it as
    a reason the mechanism does not belong in the validated boundary.

11. **Section 11.6's in-kernel oversubscription test is pending.** The 28%
    ECDSA-sign loss for the shared RNG at 2x oversubscription is measured and
    real in userspace. The hypothesis that in-kernel non-preemptibility
    (`local_bh_disable()`, `SAVE_VECTOR_REGISTERS`) removes it is **untested**.
    Do not report an outcome until that test lands.

12. **aarch64 and AES-GCM-SIV carry multi-lane CPUID selection.** aarch64 AES
    selects between the Armv8 crypto-extension and base implementations from
    `IS_AARCH64_AES`; aarch64 SHA-256 selects three-way between
    `_crypto_aarch64`, `_neon_aarch64` and the C `Transform_Sha256_Len`; and
    AES-GCM-SIV keeps a full ladder on both architectures (`AesGcmSivCtrAsm()`
    selecting `_aarch64` / `_neon` / `_base`, and `_avx512` / `_vaes` / `_avx1` /
    `_aesni` from `intel_flags`, with `AesGcmSivPolyvalAsm()` the same shape).

    **Under section 3.0 this is not a defect** — the elected posture retains
    stepping and deletes only the fallback. Two paths were read directly to
    confirm they are stepping and not fallback: aarch64 AES propagates the
    failure (`aes.c` — `int _svr_ret = AES_encrypt_AARCH32(...); if (_svr_ret !=
    0) return _svr_ret;`), and the AES-GCM-SIV region contains no
    `SAVE_VECTOR_REGISTERS`, `_svr_ret` or fallback reference at all (`aes.c`
    20500-21600), so those ladders are pure CPUID selection with nothing to fall
    back to.

    **What matters if the laboratory takes the *contained* reading:** aarch64
    AES, aarch64 SHA-256 and AES-GCM-SIV on both architectures each carry several
    compiled lanes, so they are where a per-implementation CAST obligation would
    bite hardest. Under the *reachable* reading they need nothing beyond the
    sweep below.

13. **Dispatch sweep: every aarch64 selection site is CPUID-only.** The test
    applied is section 3.0's: *can any run-time condition other than CPUID change
    which implementation runs?* Read directly on this branch. **Every aarch64
    dispatch site has now been swept for selection semantics; none has been
    audited for bracket correctness** — that is section 13.5.9's question.

    | Site | Selector |
    |---|---|
    | `aes.c:1232-1235` | `IS_AARCH64_AES` / `IS_AARCH64_PMULL` / `IS_AARCH64_SHA3` into `aes->use_*_hw_crypto`; ~30 consumer sites are plain `if (aes->use_aes_hw_crypto)` tests |
    | `aes.c:21335` (AES-GCM-SIV CTR) | `IS_AARCH64_AES` |
    | `sha256.c:1385`/`:1390` | `IS_AARCH64_SHA256`, then `IS_AARCH64_ASIMD` |
    | `sha512.c` | `IS_AARCH64_SHA512`, then `IS_AARCH64_ASIMD` |
    | `sha3.c` | `IS_AARCH64_SHA3` |
    | `wc_mlkem_poly.c:1413`, `:1500`, `:1590` | `MLKEM_LANE_ARM_RDM()`, which is `IS_AARCH64_RDM()` |
    | `chacha.c`, `poly1305.c` | `IS_AARCH64_ASIMD` — not approved algorithms |

    No aarch64 arm conditions a selection on vector-register save success, on
    length, on alignment, or on module state. The aarch64 asm entry points are
    `void` and are chosen before they are called, never after a failure.

    **The one capability-driven selection in the tree is x86 and is already
    excluded.** `sha3.c` sets `SHA3_BLOCK = BlockSha3` when
    `! CAN_SAVE_VECTOR_REGISTERS()`. It sits inside `USE_INTEL_SPEEDUP` **and**
    inside `#if defined(WC_C_DYNAMIC_FALLBACK) &&
    defined(WC_ALLOW_RUNTIME_IMPL_SELECT)`, neither of which is defined in a
    certified build.

    **x86 ML-KEM and ML-DSA** are converted: every one of the ~125 sites uses the
    file's own fail-closed macro — `MLKEM_SVR_OR_RETURN()` /
    `MLDSA_SVR_OR_RETURN()`, which returns the save error — so CPUID alone selects
    the lane and a save failure ends the call.
    `scripts/fips-no-svr-fallback-check.sh` reports 0 live sites in both files.

    **`wc_frodokem_mat.c` has the fallback shape at ~12 x86 sites.** FrodoKEM is
    not an approved algorithm and is outside the module boundary, so it is
    recorded for completeness rather than as a finding.

    **What the gate cannot see, stated so a pass is not over-read.**
    `scripts/fips-no-svr-fallback-check.sh` scans `wolfcrypt/src/*.c` only. The
    LKCAPI glue in `linuxkm/*.c` is outside its file list and cannot be added:
    the glue includes kernel headers, so the gate cannot preprocess it, and on a
    userspace-configured tree those files are not compiled at all. That blind
    spot is how `WC_LINUXKM_C_FALLBACK_IN_SHIMS` (section 3.0) went unreported
    for so long. The gate now additionally asserts that both halves of that
    macro's guard are intact, which is a source-text assertion rather than a
    preprocessed one — it proves the guard exists, not that a build honours it.
    The `#error` does the latter, by failing the compile. **Run-time
    implementation selection introduced anywhere else in `linuxkm/*.c` would
    still not be caught by this gate.**

14. **Some measurements and citations predate the removal of the per-algorithm
    configure-time lane-selection surface, and cannot be reproduced from this
    tree.** The `--with-fips-<alg>-impl` options and their check script no longer
    exist. Section 12.1's arms B and B2 were built with that surface; their
    numbers are not reproducible here. Either land the artifacts or drop the
    figures.

    Related: **the evidence trees under `matrix/` and `evidence/` are not in this
    repository.** Item 1 concedes it for one measurement; it is true of all of
    them.

15. **The `irqs_disabled()` refusal is a deliberate availability reduction, and
    nobody has priced it.** This is the strongest argument against the change in
    this document.

    **What changed.** `wc_save_vector_registers_x86()` refuses NMI context,
    hard-interrupt context, **and IRQs-disabled task context**, returning
    `WC_ACCEL_INHIBIT_E` (`linuxkm/x86_vector_register_glue.c`, the
    `preempt_count() & (NMI_MASK | HARDIRQ_MASK)` / `irqs_disabled()` test in both
    `wc_can_save_vector_registers_x86()` and `wc_save_vector_registers_x86()`).
    The `irqs_disabled()` half is **new on this branch**: `git show
    <branch>:linuxkm/x86_vector_register_glue.c | grep -c irqs_disabled` returns
    0 on `with-fallback-aug6`, 0 on `PQ-FS-2026-Part2`, and 0 on `master`. Before
    it, a caller arriving from an IRQs-disabled region proceeded and ran the C
    twin. **So this is a context the fallback was serving and the module now
    refuses**, which is exactly the objection section 1 has to answer rather than
    omit.

    **What it costs, as far as anyone has actually checked.**
    * **Softirq context is still permitted, explicitly** — including a timer
      callback on the pid-0 idle task. The refusal is much narrower than "atomic
      context", and section 5's DRBG-in-softirq case is unaffected.
    * **The two consumers usually named are not exposed.** dm-crypt runs its
      crypt and io work from workqueues (`drivers/md/dm-crypt.c`, `io_queue` /
      `crypt_queue`) and IPsec ESP runs from softirq (`net/ipv4/esp4.c`) — both
      IRQs-enabled. Neither can reach the refusal. Checked against Linux 6.12.59.
    * **When it does fire, the consequence is availability, not correctness.** The
      wolfCrypt error propagates out of the LKCAPI glue as `-EINVAL`
      (`linuxkm/lkcapi_sha_glue.c` shash ops; `linuxkm/lkcapi_aes_glue.c` setkey
      and skcipher/AEAD paths). A consumer maps that onward the way it maps any
      crypto failure — dm-crypt to `BLK_STS_IOERR` (`dm-crypt.c:2152`, `:2295`),
      ESP by dropping the skb (`esp4.c:158`). Nothing produces a wrong digest or
      wrong ciphertext.
    * **The one correctness-shaped consequence has been closed.** A consumer that
      ignored an `->update()` error and called `->final()` anyway used to get a
      digest of the *partial* message with a success status. The shash glue now
      latches the failure in the descriptor and `->final()` returns `-EINVAL`.

    **What is not established, and this is the limitation.** Nobody has
    enumerated the in-kernel callers that can reach this module with interrupts
    disabled. There is no trace, no measurement, and no matrix cell that
    exercises the refusal. The bullets above bound the cost **by argument, not by
    evidence** — they rule out the consumers someone thought of, which is not the
    same as ruling out the set. And a consumer that genuinely needs crypto from
    an IRQs-disabled region has no retry path: the contract change lands on it,
    and no consumer has been asked. **Do not cite this section as "the
    availability change is free."** It is "the exposure looks narrow and has not
    been measured."

16. **The certification question in section 3.1.1 is open and has not been put to
    the laboratory.** Neither has the category A / category B split of section
    3.4.1.

17. **The systematic audit described in Appendix A has not been performed.**
    Everything in this section is a statement about what is not known, and it
    should not be read as a bounded list.

---

## Appendix A. The pattern, and what would close it

### A.1 The same shape, four times

Four structures in this module were built the same way, and the resemblance is
not incidental. **None of the four is compiled into a certified module today**;
the table records how they came to be written, which is the part no fix changes.

| | Justified by | Actual behaviour | In a certified build |
| :--- | :--- | :--- | :--- |
| `WC_C_DYNAMIC_FALLBACK` (section 2) | "the save might fail" | silently substituted an untested implementation | refused at compile time |
| `rng_bank` (section 11) | "the DRBG might contend" | 0.16% on the served workload, new failover surface | compiled out |
| cross-CPU slot scan (section 13.3) | "a thread might migrate" | cannot happen; if it did, corrupts bracket accounting | not in the translation unit |
| ownership arbitration (section 13.4) | "a slot might be stale" | evicted a slot claimed 1 ms earlier, 20 of 20; does not fire on the state a real leak produces | not in the translation unit |

Each was introduced to survive a scenario that was **asserted rather than
demonstrated**, none carries a reproducer or a matrix cell that exercises it, and
in each case the defensive path is less sound than the condition it guards. The
fourth is the sharpest: it answers a question the kernel never delegated to the
module, and the kernel provides no interface for answering it.

The last column is the reason this appendix is short. Each was removed by
deciding what the module's job actually is — section 1's rule — rather than by
making the machinery work.

The consistent failure is methodological: **a hypothesis about kernel behaviour
was treated as a requirement without first reading what the kernel guarantees.**

### A.2 The guarantees were available in advance

The kernel guarantees relied on in section 13.3 are neither obscure nor recent.
`kernel_fpu_begin()` has disabled preemption for the life of the section for many
releases, and it is eleven lines of `arch/x86/kernel/fpu/core.c`.
`locktypes.rst` exists to tell driver authors which primitive gives which
guarantee. `floating-point.rst` states the module's whole obligation in four
sentences. **The information required to not write this code was available before
it was written.**

### A.3 Why the count of problems is not a measure of the problem

Three properties of everything in this document deserve to be stated together:

1. **Every issue was found by reading, not by a test failing.** No test in the
   suite exercised any of these paths.
2. **The defensive structures could not be tested.** Code written to recover from
   a state the operating system's own locking prevents cannot be reached by any
   test that respects that locking. Its defect was findable only by reading, and
   would not have been found by any amount of running.
3. **Nobody went looking systematically.** The fallback was found while
   investigating something else. The AES build setting was found while writing up
   the fallback. The slot machinery was found while writing up the fallback. The
   unbracketed ECC AVX2 was found while checking the slot machinery.

A count of defects found under those conditions is a count of what one reader
noticed on the way to somewhere else. It says very little about what remains. The
correct statement to a reviewer, to management and to the laboratory is that we
do not currently know what else is in this code, and we do not have a process
that would tell us.

### A.4 What would change that

In rough order of value for effort:

1. **A deliberate audit of every place the module answers a question the
   operating system already answers.** The test to apply is a single question:
   *does any condition other than what the processor supports change which
   implementation runs, or which task holds a resource?* Wherever the answer is
   yes, that site needs justification against a quoted kernel guarantee, or it
   needs to go.
2. **A sweep of every security-relevant build setting the source documents but
   does not switch on.** The AES cache countermeasure of section 2.1.3 was one.
   Nobody has checked whether it was the only one, and the check is cheap.
3. **Coverage for the paths that have none.** Where a defensive path cannot be
   reached by a test, that is itself the finding. Either it is unreachable, in
   which case delete it, or it is reachable, in which case build the test.
4. **Capture the measurements this document reports.** Several results here are
   reported rather than filed. They should be reproducible from artifacts before
   any of them goes into a submission.
