# Kernel patches for `WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS`

Each subdirectory is a kernel version and holds one patch against that version's
`drivers/char/random.c` and `include/linux/random.h`. The patch adds the
callback hooks that let the wolfSSL kernel module service the kernel's
`get_random_bytes()` family, so that randomness the kernel hands out is
generated inside the FIPS module boundary rather than by the kernel's own
generator.

## An unlisted kernel version is NOT an unsupported one

There are twelve directories here and thirty-four supported kernel versions. The
twelve are **bases**, not the list of what is supported. Most supported versions
are served by a patch derived from a base belonging to a different version --
often a different series. If your version has no directory of its own, look it
up in the coverage table below; it is almost certainly there.

The mapping is many-to-one and it is **not** nearest-by-version. See "Why the
numbers do not order the way you expect" before assuming which base serves you.

## Coverage: every supported version, and the patch that serves it

Confidence is one of:

| marker | meaning |
|---|---|
| `SHIPPED` | the directory named for this series serves the tested patchlevel directly |
| `DERIVED (verified)` | derived from the named base, and the result was confirmed to apply AND to compile `drivers/char/random.o` |
| `DERIVED (unverified)` | believed to derive, not confirmed |
| `NOT COVERED` | no base works |

Every row below was confirmed by applying the base patch to a pristine tree at
the stated patchlevel, running the derivation, and compiling
`drivers/char/random.o` against the result. There are no `NOT COVERED` rows and
no `DERIVED (unverified)` rows.

| version | verified at | patch that serves it | confidence |
|---|---|---|---|
| 5.6  | 5.6.19    | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`             | DERIVED (verified) |
| 5.7  | 5.7.19    | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`             | DERIVED (verified) |
| 5.8  | 5.8.18    | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`             | DERIVED (verified) |
| 5.9  | 5.9.16    | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`             | DERIVED (verified) |
| 5.10 | 5.10.265  | `5.10.236/WOLFSSL_KERNELv5_10_236_FIPS.patch`           | SHIPPED |
| 5.11 | 5.11.22   | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                   | DERIVED (verified) |
| 5.12 | 5.12.19   | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                   | DERIVED (verified) |
| 5.13 | 5.13.19   | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                   | DERIVED (verified) |
| 5.15 | 5.15.216  | `5.17-ubuntu-jammy-tegra/WOLFSSL_KERNELv5_17_tegra_FIPS.patch` | DERIVED (verified) |
| 5.16 | 5.16.20   | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                   | DERIVED (verified) |
| 5.17 | 5.17.15   | `5.17.14/WOLFSSL_KERNELv5_17_14_FIPS.patch`             | SHIPPED |
| 5.18 | 5.18.19   | `5.10.236/WOLFSSL_KERNELv5_10_236_FIPS.patch`           | DERIVED (verified) |
| 5.19 | 5.19.17   | `6.1.73/WOLFSSL_KERNELv6_1_73_FIPS.patch`               | DERIVED (verified) |
| 6.0  | 6.0.19    | `6.1.73/WOLFSSL_KERNELv6_1_73_FIPS.patch`               | DERIVED (verified) |
| 6.1  | 6.1.183   | `6.1.73/WOLFSSL_KERNELv6_1_73_FIPS.patch`               | SHIPPED |
| 6.2  | 6.2.16    | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.4  | 6.4.16    | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.5  | 6.5.13    | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.6  | 6.6.152   | `6.12.75/WOLFSSL_KERNELv6_12_75_FIPS.patch`             | DERIVED (verified) |
| 6.7  | 6.7.12    | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.8  | 6.8.12    | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.9  | 6.9.12    | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.10 | 6.10.14   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.11 | 6.11.11   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                   | DERIVED (verified) |
| 6.12 | 6.12.104  | `6.12.75/WOLFSSL_KERNELv6_12_75_FIPS.patch`             | SHIPPED |
| 6.13 | 6.13.12   | `6.15/WOLFSSL_KERNELv6_15_FIPS.patch`                   | DERIVED (verified) |
| 6.14 | 6.14.11   | `6.15/WOLFSSL_KERNELv6_15_FIPS.patch`                   | DERIVED (verified) |
| 6.15 | 6.15.11   | `6.15/WOLFSSL_KERNELv6_15_FIPS.patch`                   | SHIPPED |
| 6.16 | 6.16.12   | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                     | DERIVED (verified) |
| 6.17 | 6.17.13   | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                     | DERIVED (verified) |
| 6.18 | 6.18.45   | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                     | DERIVED (verified) |
| 6.19 | 6.19.14   | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                     | DERIVED (verified) |
| 7.0  | 7.0.14    | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                     | SHIPPED |
| 7.1  | 7.1.9     | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                     | DERIVED (verified) |

Four of the twelve directories are never the best base for any supported version
and are kept for the specific trees they were authored against:

| directory | serves |
|---|---|
| `5.10.17`               | 5.10.17 itself, and the 5.6-5.9 derivations above |
| `5.14.0-570.58.1.el9_6` | the RHEL 9.6 vendor kernel, which is not in the supported list |
| `5.17`                  | 5.17.12 and 5.17.13 only; see "A series can change shape mid-series" |
| `6.12`                  | 6.12.0 through 6.12.74; see "A series can change shape mid-series" |

### The row is per patchlevel, not per series

The table states the patchlevel each row was verified at, because the answer
**changes within a series**. Do not read a row as covering every `.y` of that
series.

`5.10.17` does not apply to 5.10.265 and `5.15` does not apply to 5.15.216;
both of those series took the 5.18 random.c rewrite as a stable backport
partway through their lifetime.

### A series can change shape mid-series

Two series change `random.c` API shape at a known patchlevel, so each needs two
patches. The seam was measured by applying at `--fuzz=0` to every patchlevel
across the boundary, not inferred:

| series | patchlevels | patch |
|---|---|---|
| 5.17 | 5.17.12 - 5.17.13 | `5.17/WOLFSSL_KERNELv5_17_FIPS.patch` |
| 5.17 | 5.17.14 - 5.17.15 | `5.17.14/WOLFSSL_KERNELv5_17_14_FIPS.patch` |
| 6.12 | 6.12.0 - 6.12.74  | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch` |
| 6.12 | 6.12.75 - 6.12.104+ | `6.12.75/WOLFSSL_KERNELv6_12_75_FIPS.patch` |

**6.12 flips at 6.12.75.** Stable backported "Remove WARN_ALL_UNSEEDED_RANDOM
kernel config option" (Linus Torvalds, 2026-03-04, mainline 6.18), which deletes
the `warn_unseeded_randomness()` macro and its two call sites. That breaks two
hunks of the `6.12` patch: hunk 6 *edits* the macro, and hunk 9 carries one of
its calls in context. Fuzz rescues hunk 9 but never hunk 6, because the lines it
edits no longer exist -- which is why `--fuzz=3` does not help. The `6.12.75`
patch is the `6.12` patch with hunk 6 dropped and hunk 9's context refreshed;
the `crng_ready()` -> `crng_ready_maybe_cb()` substitutions are unchanged and
land at the same nine sites.

The same backport reached **6.6 at 6.6.128**, which is why `6.12.75` -- not
`7.0` -- is the closest fit for current 6.6 as well.

**5.17 flips twice.** 5.17.0-5.17.11 predate the 5.18 `random.c` rewrite;
5.17.12 took the rewrite *and* the `crng_is_ready` static key as a stable
backport; 5.17.14 then **reverted the static key** while keeping the rewrite. So
5.17 runs pre-rewrite -> static key -> no static key, and the middle window is
two patchlevels wide. `5.17` serves that middle window; `5.17.14` serves the
final two. 5.17.0-5.17.11 has no patch and no base that applies to it at any
fuzz level.

### Why the numbers do not order the way you expect

`drivers/char/random.c` was rewritten in 5.18 (`extract_crng_user` and
`urandom_read` gave way to `get_random_bytes_user` and `urandom_read_iter`).
The rewrite was then **backported into the LTS branches and not into the
others**, so API shape does not follow version order:

| shape | versions |
|---|---|
| pre-rewrite (`extract_crng_user`) | 5.6, 5.7, 5.8, 5.9, 5.11, 5.12, 5.13, 5.16 |
| post-rewrite (`get_random_bytes_user`) | 5.10, 5.15, 5.17 and everything newer |

5.10 and 5.15 are LTS and took the backport. 5.11, 5.12, 5.13 and 5.16 reached
end of life first and never did. So 5.10 is *newer in API* than 5.13, and 5.15
is newer in API than 5.16, even though the numbers say otherwise. A
nearest-by-number rule is wrong across that entire span, which is why the table
above exists and why it is derived from measurement rather than arithmetic.

A second boundary sits inside the 6.x line: `crng_reseed()` took a
`struct work_struct *` argument in **6.2**. A base from either side of that
boundary will often still *apply* to a tree on the other side, and then fail to
compile with `too few arguments to function 'crng_reseed'`. Applying is not
compiling; the table's rows were compiled.

## Naming

    WOLFSSL_KERNELv<version>_FIPS.patch

with `.` replaced by `_`. Two directories carry a distinguishing suffix instead
of their full vendor version string, because the full string is unwieldy:

| directory | patch |
|---|---|
| `5.10.17`                 | `WOLFSSL_KERNELv5_10_17_FIPS.patch` |
| `5.10.236`                | `WOLFSSL_KERNELv5_10_236_FIPS.patch` |
| `5.14.0-570.58.1.el9_6`   | `WOLFSSL_KERNELv5_14_el9_6_FIPS.patch` |
| `5.15`                    | `WOLFSSL_KERNELv5_15_FIPS.patch` |
| `5.17`                    | `WOLFSSL_KERNELv5_17_FIPS.patch` |
| `5.17.14`                 | `WOLFSSL_KERNELv5_17_14_FIPS.patch` |
| `5.17-ubuntu-jammy-tegra` | `WOLFSSL_KERNELv5_17_tegra_FIPS.patch` |
| `6.1.73`                  | `WOLFSSL_KERNELv6_1_73_FIPS.patch` |
| `6.12`                    | `WOLFSSL_KERNELv6_12_FIPS.patch` |
| `6.12.75`                 | `WOLFSSL_KERNELv6_12_75_FIPS.patch` |
| `6.15`                    | `WOLFSSL_KERNELv6_15_FIPS.patch` |
| `7.0`                     | `WOLFSSL_KERNELv7_0_FIPS.patch` |

`regen-patches.sh` derives these names from the directory name and asserts the
result against what is checked in, so the table above and the files cannot
drift apart silently.

## There are two kinds of patch, and they are not interchangeable

**Shipped (this directory, in git).** The files listed above. They define
`WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS` and use unnamespaced symbols.

**Derived (generated by the test harness, never in git).** The test harness
takes a shipped patch as a base and derives a version-specific patch whose
symbols are namespaced (`..._FIPS` defines, `wc_grb_*` counters). These are
written to a scratch output directory at test time by
`matrix/arm64/patches/make-fips-rbgc-patch.sh` and its counterpart under
`matrix/is-deferral-required/`.

Neither of those scripts chooses a base -- both take one as their second
argument. Base selection lives in their callers, and the two callers do not use
the same rule:

* `matrix/arm64/lib/kernel.sh` orders candidates by (same side of the
  `crng_reseed` boundary, then `|major.minor|` distance, then older-first) and
  takes the first that applies with `--fuzz=3`.
* `matrix/is-deferral-required/kernels-full/pass2.sh` takes the base with the
  fewest offsets among those that applied with **no** fuzz.

They disagree for some versions, and only the second matches the table above.
Which base a given harness run actually used is recorded in that run's results
(`kernel_patch_base=`), so read that rather than assuming.

Consumers locate a shipped patch by directory and glob (`<version>/*.patch`),
not by filename, so the filenames above are not a harness API.

## Regenerating

`regen-patches.sh` regenerates every patch from full kernel sources staged under
`src/<version>/`, each holding a pristine `random.c.dist` / `random.h.dist`
alongside the modified `random.c` / `random.h`. It is an internal tool: it
requires those staged trees and is not part of the library build.
