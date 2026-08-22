# Vector-register fallback: review outcome and elected design

**Status:** closed. The design described here is what v7.0.0 submits.

This document records a design decision about how the Linux kernel module
behaves when the vector registers are unavailable. It is deliberately short.

> **Note on section numbers.** Several source files cite sections of this
> document by number (2.1, 3.0, 6, 13.4, 13.5, 13.6). Those numbers are kept
> below as stable anchors so existing code comments continue to resolve. Do not
> renumber them.

---

## Summary

The Linux kernel module originally carried a **run-time fallback**: when it
could not obtain the vector registers, it quietly ran a second, software
implementation of the same algorithm and reported success.

That design was reviewed for FIPS 140-3 compliance. The review found that a
certifiable case could probably have been constructed for it — with additional
machinery to track which implementation ran, when, and under what conditions,
and with the supporting argument spelled out for the laboratory and the CMVP
reviewer.

We chose not to pursue that route. It was the most complex and least
FIPS-friendly of the available options: it would have required carrying two
implementations of each algorithm, arbitration logic to decide between them,
and per-operation indicators so that any given result could be attributed to
one of them. Every one of those elements is something a reviewer would
reasonably ask questions about, and each question costs schedule.

A simpler design was identified and adopted instead. **The module carries one
implementation of each algorithm, chosen when the module is built.** When the
vector registers are unavailable, the caller is told, and can ask again. No
second implementation exists to switch to, so nothing needs to be arbitrated
and nothing needs to be tracked.

The rest of this document lists what was not compliant in the original design
and how the elected design closes each gap.

---

## 1. The rule

One implementation per algorithm, selected at build time. If the module cannot
serve a request, it reports a retryable error to the caller. It never computes
the answer a second way, and it never lets the kernel's own implementation
answer on its behalf.

---

## 2. What was here before, and why it was removed

The original code answered "I cannot get the vector registers" by running a
different implementation and returning success. The two paths were not
interchangeable for compliance purposes, and the caller could not tell which
one had run.

## 2.1 The security property the fallback removes

A FIPS module's algorithm self-tests cover *an implementation*. When a build
contains two implementations of one algorithm and can move between them at run
time, a passing self-test no longer tells you which code produced a given
result. Restoring that certainty is possible, but only by adding tracking and
reporting machinery — which is precisely the complexity the elected design
avoids.

The elected design removes the question rather than answering it: with one
implementation compiled in, the self-test and the result describe the same
code, always.

---

## 3. What the Implementation Guidance requires, and what we elect

### 3.0 The elected posture

Two build configurations, and only two:

1. **Configured with processor acceleration (PAA).** The accelerated
   implementation is the only one compiled in. Selection on processor
   capability is retained: a write-once decision made at first use from what
   the processor reports, never revised afterwards. **There is no kernel
   fallback.** A vector-register save failure returns an error to the caller;
   it is never answered by quietly running different code and reporting
   success.
2. **Configured without PAA.** Software only. No accelerated implementation is
   compiled in.

**What was deleted is the fallback, not the processor-capability selection.**
These are different mechanisms with different consequences. Capability
selection happens once, at first use, and resolves to a single implementation
for the life of the module — the same behaviour shipped in v5.2.1, v5.2.4 and
v6.0.0. The fallback could change the answer on any individual call.

---

## Gaps in the original design, and how the elected design closes each

| # | Gap in the original design | How the elected design closes it |
|---|---|---|
| 1 | A failed vector-register acquisition was answered by running a second implementation and reporting success. | The failure is returned to the caller as a retryable error. The caller comes back to us; nothing else computes the answer. |
| 2 | Two implementations of one algorithm in a single build, reachable at run time. | One implementation per algorithm, fixed at build time. |
| 3 | Attribution: a result could not be tied to a specific implementation without extra tracking. | No tracking needed. Only one implementation exists in the build. |
| 4 | An operation could change implementation part-way through (section 6). | Nothing to change to. |
| 5 | Ownership of the vector registers required arbitration between contexts (section 13.4). | No arbitration. Sections nest per execution context and the processor is held for the life of a section. |
| 6 | Some accelerated code ran outside a save/restore bracket (section 13.5). | Those sites are bracketed. |
| 7 | The per-core DRBG bank sat inside the boundary while being described as outside it, and absorbed entropy failures without reporting them (section 11). | The bank is not part of a FIPS build. Kernel randomness is served by the RBGC design, on demand into the caller's buffer. |

---

## 6. Mid-operation implementation switching

The original design permitted a hash operation to begin on one implementation
and finish on another if the vector registers became unavailable mid-way. The
elected design cannot do this: there is only one implementation, and an
operation that cannot obtain the registers is refused before it starts rather
than switched part-way through.

---

## 11. Per-core DRBG bank, and the RBGC alternative

**What the bank actually held.** A set of instantiated DRBG instances, ready to
serve callers — **not** pre-generated random output. Generation happened into
the caller's own buffer at the time of the request, and nothing was retained
afterwards. On that specific point the design was sound.

**What was actually wrong with it**, in the order a reviewer would care:

1. **It was described as being outside the cryptographic module boundary, and it
   was not.** In every FIPS configuration its object was compiled between the
   two boundary markers and covered by the in-core integrity hash.

   The decisive point is the direction of the dependency. Code that genuinely
   sits outside the boundary only ever calls *into* it; nothing inside depends
   on it. Here the coupling ran both ways — the module's own random-number
   generation called *out* to the bank, and the bank called back in through the
   module's approved-service wrappers. Removing the bank from the FIPS build
   therefore broke the link, and the three unresolved references named the
   dependency precisely: two in the generate path and one in the teardown path
   of the module's RNG.

   (Relocating the file *below* the boundary marker, rather than removing it
   from the FIPS build, does link — but it changes nothing that matters. The
   in-boundary calls remain, now reaching code the integrity check no longer
   covers. Neither move made the original claim true.)

2. **An entropy or reseed failure was absorbed rather than reported.** The
   failing instance was destroyed, a fresh one instantiated in its place, the
   request retried, and success returned to the caller. There was a
   rate-limited kernel log line, but no counter, no status, no return code and
   no module state change — so nothing above it could learn that it had
   happened. (The stricter case is better than it looks: a continuous
   health-test failure was *not* absorbed. It propagated and drove the module
   into its failed state, as it should.)

3. **It leaned on a very large reseed interval.** In kernel builds the interval
   is 2^48 requests rather than the 1,000,000 used elsewhere. That value is the
   ceiling SP 800-90A permits, so it is compliant rather than excessive — but
   the limit is finite, the behaviour at the limit is to steer callers to a
   different instance, and if every instance is due at once the request falls
   through to a blocking entropy poll in a context that may not tolerate one.
   The interval is also a global build setting, not something the bank
   introduced.

4. **It reached directly into DRBG internal state.** The force-a-reseed path
   wrote the DRBG's own reseed counter from outside the DRBG, then generated
   and discarded four bytes to make the reseed happen. On builds with a 32-bit
   counter that write truncated to zero and did the opposite of its purpose.

5. **Instance nonces were derived from memory addresses**, so they were
   predictable across the bank and — because re-instantiation reused the same
   slot — identical to the nonce of the instance just destroyed.

**How this is resolved.** The bank is not part of a FIPS build. It is compiled
in only under its own build option, outside the FIPS source lists entirely, so
none of the above applies to the submitted module. That is a cleaner answer than
relocating it would have been: the question of what it is coupled to does not
arise if it is not there.

The elected design is described in **`RBGC-design.md`**. It is the more
streamlined alternative: randomness is generated **in direct response to a
request, into the requester's own buffer, with nothing retained afterwards**,
and it **does not require changing the reseed interval**.

> Coverage note: testing of the RBGC design across the full range of kernel
> versions and architectures is in progress at the time of writing. This
> document will state the covered range once those results are complete and
> filed with the submission evidence.

---

## 13. Which implementation runs, and when that is decided

Decided once, at build time, with processor-capability selection resolved at
first use and never revised. There is no per-call decision to describe.

### 13.4 Vector-register ownership

The original design maintained a table of which execution context owned the
vector registers on each processor, with logic to arbitrate competing claims.
The elected design does not arbitrate: each execution context has its own
state, sections nest, and the processor is held for the life of a section, so
two contexts cannot contend for the same registers.

### 13.5 Accelerated code outside a save/restore bracket

Some accelerated arithmetic used vector registers without first saving the
interrupted state. Those sites are now bracketed, so the registers are always
saved before use and restored afterwards.

### 13.6 Integrity coverage of ARM relocation targets

On ARM builds, certain relocation targets fell outside the range covered by the
module's in-core integrity check. This is tracked as an integrity-coverage item
and is addressed separately from the fallback question; it is recorded here
because existing source comments reference this section number.

---

## 14. Limitations

This document is a summary. Where a precise claim is needed — the exact wording
of a guarantee, the conditions under which it holds, or the measurements behind
it — use the submission and testing evidence.
