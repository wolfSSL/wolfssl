# Kernel patches for `WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS`

Each subdirectory is a kernel version and holds one patch against that version's
`drivers/char/random.c` and `include/linux/random.h`. The patch adds the
callback hooks that let the wolfSSL kernel module service the kernel's
`get_random_bytes()` family, so that randomness the kernel hands out is
generated inside the FIPS module boundary rather than by the kernel's own
generator.

## An unlisted kernel version is NOT an unsupported one

There are seventeen directories here and thirty-four supported kernel versions.
The seventeen are **bases**, not the list of what is supported. Most supported
versions are served by a patch derived from a base belonging to a different
version -- often a different series. If your version has no directory of its
own, look it up in the coverage table below; it is almost certainly there.

The mapping is many-to-one and it is **not** nearest-by-version. See "Why the
numbers do not order the way you expect" before assuming which base serves you.

## Coverage: every supported version, and the patch that serves it

Two columns carry the evidence, and they are deliberately separate:

| column | meaning |
|---|---|
| `source` | Where the patch FILE lives -- provenance only, NOT a confidence level. `SHIPPED` means a directory named for this series serves it directly; `DERIVED` means a base belonging to another series serves it. **A DERIVED row is tested exactly as hard as a SHIPPED one** -- see the `tested` column, which is what says whether it was verified. |
| `tested` | `TESTED` -- on 2026-08-22 this row was measured end to end: the patch applied at `--fuzz=0`, `drivers/char/random.o` was built from the patched tree with no diagnostic the pristine tree did not also emit, the symbols the module binds to were present AND exported, and a consumer translation unit using those declarations the way `linuxkm/module_hooks.c` does compiled. 39 of 39 rows passed all four. Controls: a wrong-side base fails to compile; a deleted `EXPORT_SYMBOL_GPL` still COMPILES CLEAN while reading NOT-EXPORTED, which is why 'it compiles' is not the test. |

**Every row applies at `--fuzz=0`.** That was re-measured for all thirty-four
supported versions against all seventeen bases -- 578 cells -- so there are no
`NOT COVERED` rows.

**Every row has now been compiled**, on x86_64 `defconfig`, each against its own
pristine baseline build so that a diagnostic is only counted when the patch is
what introduced it. Compiling matters separately from applying: a base from the
wrong side of the 6.2 `crng_reseed()` boundary applies at `--fuzz=3` and then
fails with `too few arguments to function 'crng_reseed'`, and a fuzzed hunk can
land in a function where its variables do not exist.

Compiling is not the end of it either, which is why the column also covers the
symbols. A patched `random.c` can compile perfectly and still export a name the
module does not call, in which case `libwolfssl.ko` loads against nothing --
`insmod` fails with `Unknown symbol wolfssl_linuxkm_register_random_bytes_handlers
(err -2)`. Both halves are checked per row.

**`--fuzz=0` is the bar here, and it is not the bar the harness uses.**
`make-fips-rbgc-patch.sh` fuzzes at 3 unconditionally. Fuzz drops context lines
until a hunk matches *something*, so a hunk can land in the wrong function
entirely and still be reported as applied. That is not hypothetical: the `5.15`
base on a 5.17.11 tree puts its `mix_pool_bytes()` hunk inside `fast_mix()` at
`--fuzz=3`, and the kernel then will not build.

## Applying a patch to a kernel

```sh
./patch-kernel.sh /path/to/linux-6.6.99            # picks the tested base for you
./patch-kernel.sh --dry-run /path/to/linux-7.1.9   # check first, write nothing
./patch-kernel.sh /path/to/linux-6.6.99 6.12       # force a base, if you must
```

With no base argument the script reads `VERSION`/`PATCHLEVEL`/`SUBLEVEL` out of
the kernel's own `Makefile` and looks the version up in the table below, so you
get the base that was **tested** for your version rather than the one whose
directory name looks closest.

**It applies at `--fuzz=0` and refuses if that fails. That refusal is the
feature.** `patch(1)` will place a hunk in the wrong function when context has
drifted, and exit 0 while doing it. That is not hypothetical here: applying the
`5.15` base to a 5.17 tree at `--fuzz=3` put the `mix_pool_bytes()` hunk inside
`fast_mix()`, and the tree then failed to build with
`random.c:915: error: 'in' undeclared`. A marker count cannot detect this --
the count is identical either way. If the script refuses, your version needs a
base of its own; raising the fuzz is never the answer.

Doing it by hand is the same two commands:

```sh
patch -p1 -d <kernel> --dry-run --fuzz=0 < <series>/WOLFSSL_KERNELv<series>_FIPS.patch
patch -p1 -d <kernel>            --fuzz=0 < <series>/WOLFSSL_KERNELv<series>_FIPS.patch
```

If the kernel is left unpatched, nothing silently degrades: the module fails to
load with `Unknown symbol wolfssl_linuxkm_register_random_bytes_handlers`
rather than running without the hook. See `linuxkm/README.md`.

| version | verified at | patch that serves it | source | tested |
|---|---|---|---|---|
| 5.6  | 5.6.19   | `5.6/WOLFSSL_KERNELv5_6_FIPS.patch`                            | SHIPPED | TESTED |
| 5.7  | 5.7.19   | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`                    | DERIVED | TESTED |
| 5.8  | 5.8.18   | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`                    | DERIVED | TESTED |
| 5.9  | 5.9.16   | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`                    | DERIVED | TESTED |
| 5.10 | 5.10.17  | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch`                    | SHIPPED | TESTED |
| 5.10 | 5.10.265 | `5.10.236/WOLFSSL_KERNELv5_10_236_FIPS.patch`                  | SHIPPED | TESTED |
| 5.11 | 5.11.22  | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                          | DERIVED | TESTED |
| 5.12 | 5.12.19  | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                          | DERIVED | TESTED |
| 5.13 | 5.13.19  | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                          | DERIVED | TESTED |
| 5.15 | 5.15     | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch`                          | SHIPPED | TESTED |
| 5.15 | 5.15.216 | `5.17-ubuntu-jammy-tegra/WOLFSSL_KERNELv5_17_tegra_FIPS.patch` | DERIVED | TESTED |
| 5.16 | 5.16.20  | `5.16/WOLFSSL_KERNELv5_16_FIPS.patch`                          | SHIPPED | TESTED |
| 5.17 | 5.17.11  | `5.17.0/WOLFSSL_KERNELv5_17_0_FIPS.patch`                      | SHIPPED | TESTED |
| 5.17 | 5.17.13  | `5.17/WOLFSSL_KERNELv5_17_FIPS.patch`                          | SHIPPED | TESTED |
| 5.17 | 5.17.15  | `5.17.14/WOLFSSL_KERNELv5_17_14_FIPS.patch`                    | SHIPPED | TESTED |
| 5.18 | 5.18.19  | `5.18/WOLFSSL_KERNELv5_18_FIPS.patch`                          | SHIPPED | TESTED |
| 5.19 | 5.19.17  | `6.1.73/WOLFSSL_KERNELv6_1_73_FIPS.patch`                      | DERIVED | TESTED |
| 6.0  | 6.0.19   | `6.1.73/WOLFSSL_KERNELv6_1_73_FIPS.patch`                      | DERIVED | TESTED |
| 6.1  | 6.1.183  | `6.1.73/WOLFSSL_KERNELv6_1_73_FIPS.patch`                      | SHIPPED | TESTED |
| 6.2  | 6.2.16   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.4  | 6.4.16   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.5  | 6.5.13   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.6  | 6.6.99   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.6  | 6.6.152  | `6.12.75/WOLFSSL_KERNELv6_12_75_FIPS.patch`                    | DERIVED | TESTED |
| 6.7  | 6.7.12   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.8  | 6.8.12   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.9  | 6.9.12   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.10 | 6.10.14  | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.11 | 6.11.11  | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch`                          | DERIVED | TESTED |
| 6.12 | 6.12.104 | `6.12.75/WOLFSSL_KERNELv6_12_75_FIPS.patch`                    | SHIPPED | TESTED |
| 6.13 | 6.13.12  | `6.15/WOLFSSL_KERNELv6_15_FIPS.patch`                          | DERIVED | TESTED |
| 6.14 | 6.14.11  | `6.15/WOLFSSL_KERNELv6_15_FIPS.patch`                          | DERIVED | TESTED |
| 6.15 | 6.15.11  | `6.15/WOLFSSL_KERNELv6_15_FIPS.patch`                          | SHIPPED | TESTED |
| 6.16 | 6.16.12  | `6.16/WOLFSSL_KERNELv6_16_FIPS.patch`                          | SHIPPED | TESTED |
| 6.17 | 6.17.13  | `6.16/WOLFSSL_KERNELv6_16_FIPS.patch`                          | DERIVED | TESTED |
| 6.18 | 6.18.45  | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                            | DERIVED | TESTED |
| 6.19 | 6.19.14  | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                            | DERIVED | TESTED |
| 7.0  | 7.0.14   | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                            | SHIPPED | TESTED |
| 7.1  | 7.1.9    | `7.0/WOLFSSL_KERNELv7_0_FIPS.patch`                            | DERIVED | TESTED |

One of the seventeen directories is never named by a row above, because the
version it was authored against is not in the supported list:

| directory | serves |
|---|---|
| `5.14.0-570.58.1.el9_6` | the RHEL 9.6 vendor kernel |

The 5.17 series occupies three rows rather than one, because it changes API
shape twice inside the series. See "A series can change shape mid-series".

### The row is per patchlevel, not per series

The table states the patchlevel each row was verified at, because the answer
**changes within a series**. Do not read a row as covering every `.y` of that
series.

`5.10.17` does not apply to 5.10.265 and `5.15` does not apply to 5.15.216;
both of those series took the 5.18 random.c rewrite as a stable backport
partway through their lifetime.

### A series can change shape mid-series

Two series change `random.c` API shape at a known patchlevel, so each needs more
than one patch. Every seam was measured by applying at `--fuzz=0` to every
patchlevel across the boundary, not inferred:

| series | patchlevels | patch |
|---|---|---|
| 5.10 | 5.10.17 and earlier* | `5.10.17/WOLFSSL_KERNELv5_10_17_FIPS.patch` |
| 5.10 | up to 5.10.265* | `5.10.236/WOLFSSL_KERNELv5_10_236_FIPS.patch` |
| 5.15 | 5.15 and earlier* | `5.15/WOLFSSL_KERNELv5_15_FIPS.patch` |
| 5.15 | up to 5.15.216* | `5.17-ubuntu-jammy-tegra/WOLFSSL_KERNELv5_17_tegra_FIPS.patch` |
| 5.17 | 5.17.0 - 5.17.11  | `5.17.0/WOLFSSL_KERNELv5_17_0_FIPS.patch` |
| 5.17 | 5.17.12 - 5.17.13 | `5.17/WOLFSSL_KERNELv5_17_FIPS.patch` |
| 5.17 | 5.17.14 - 5.17.15 | `5.17.14/WOLFSSL_KERNELv5_17_14_FIPS.patch` |
| 6.6  | 6.6.0 - 6.6.127   | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch` |
| 6.6  | 6.6.128 - 6.6.152+ | `6.12.75/WOLFSSL_KERNELv6_12_75_FIPS.patch` |
| 6.12 | 6.12.0 - 6.12.74  | `6.12/WOLFSSL_KERNELv6_12_FIPS.patch` |
| 6.12 | 6.12.75 - 6.12.104+ | `6.12.75/WOLFSSL_KERNELv6_12_75_FIPS.patch` |

`*` **5.10 and 5.15: the exact patchlevel at which each flips is NOT measured.**
What is measured is that both ends need different bases and each refuses the
other's, at `--fuzz=0`:

| tree | `5.10.17` | `5.10.236` |
|---|---|---|
| 5.10.17  | applies | refuses |
| 5.10.265 | refuses | applies |

| tree | `5.15` | `5.17-ubuntu-jammy-tegra` |
|---|---|---|
| 5.15     | applies | refuses |
| 5.15.216 | refuses | applies |

If your 5.10 or 5.15 patchlevel is between those points, try both and take the
one that applies with **no** fuzz. Do not take the one that applies with fuzz.

**5.10 and 5.15 flip too**, for the same reason 6.6 does: the 5.18 `random.c`
rewrite was backported into both LTS branches partway through their lifetime.

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
`7.0` -- is the closest fit for current 6.6 as well. **So 6.6 has the same seam
6.12 has**, and both sides of it are measured: on 6.6.99 the `6.12` patch
applies at `--fuzz=0` and `6.12.75` fails hunk 8; on 6.6.152 it is the other way
round. 6.6 is LTS and most 6.6 deployments are below 6.6.128, so this is the
seam a reader is most likely to land on.

**5.17 flips twice.** 5.17.0-5.17.11 predate the 5.18 `random.c` rewrite;
5.17.12 took the rewrite *and* the `crng_is_ready` static key as a stable
backport; 5.17.14 then **reverted the static key** while keeping the rewrite. So
5.17 runs pre-rewrite -> static key -> no static key, and the middle window is
two patchlevels wide. All three windows now have a base, and each refuses the
other two windows at `--fuzz=0` rather than half-applying into them.

### Why the numbers do not order the way you expect

`drivers/char/random.c` was rewritten in 5.18 (`extract_crng_user` and
`urandom_read` gave way to `get_random_bytes_user` and `urandom_read_iter`).
The rewrite was then **backported into the LTS branches and not into the
others**, so API shape does not follow version order:

| shape | versions |
|---|---|
| pre-rewrite (`extract_crng_user`) | 5.6, 5.7, 5.8, 5.9, 5.11, 5.12, 5.13, 5.16, 5.17.0 - 5.17.11 |
| post-rewrite (`get_random_bytes_user`) | 5.10, 5.15, 5.17.12+, 5.18 and everything newer |

5.10 and 5.15 are LTS and took the backport. 5.11, 5.12, 5.13 and 5.16 reached
end of life first and never did. So 5.10 is *newer in API* than 5.13, and 5.15
is newer in API than 5.16, even though the numbers say otherwise. A
nearest-by-number rule is wrong across that entire span, which is why the table
above exists and why it is derived from measurement rather than arithmetic.

A second boundary sits inside the 6.x line: `crng_reseed()` took a
`struct work_struct *` argument in **6.2**. A base from either side of that
boundary will often still *apply* to a tree on the other side, and then fail to
compile with `too few arguments to function 'crng_reseed'`. Applying is not
compiling, which is why the coverage table carries a separate `random.o built`
column instead of treating a clean apply as the end of the question.

### Why each of the newer bases exists

These five bases were added because the nearest existing base missed by one or
two hunks at `--fuzz=0`. In every case the miss is a real difference in the
tree, not patch rot:

| base | what the tree has that the nearest base did not expect |
|---|---|
| `5.6`    | `include/linux/random.h` ends after `next_pseudo_random32()`. The `arch_get_random_*_early()` inlines that `5.10.17`'s header hunk carries as context arrived in 5.7. Only the header hunk differs; the `random.c` edits are `5.10.17`'s. |
| `5.16`   | `static bool crng_need_final_init = false;` sits between `crng_init` and `#define crng_ready()`, which is context for `5.15` hunk 2. One line; everything else is `5.15`. |
| `5.17.0` | pre-rewrite like `5.15`, but 5.17 took the `random.c` cleanup series: `mix_pool_bytes()` lost its `struct entropy_store *`, `_warn_unseeded_randomness()` folded onto one line, `urandom_read()` lost `unsigned long flags`, and `crng_reseed()` became `crng_reseed(&primary_crng, bool)`. That last one matters: under fuzz the `RNDRESEEDCRNG` hunk *applies* and then will not compile, because the code it inserts calls the old two-pool signature. |
| `5.18`   | `urandom_read_iter()` gained the opportunistic `try_to_generate_entropy()` block, so it has **two** `crng_ready()` tests where `5.10.236` has one. Both are converted, matching `6.1.73`. This is a third shape, not a near-miss. |
| `6.16`   | still has `warn_unseeded_randomness()`, which `7.0` does not (removed in mainline 6.18). The macro is edited to use `crng_ready_maybe_cb()` and the batched-entropy hunk carries the call in context, exactly as `6.15` does. Serves 6.17 as well. |

Two of these five change the result and three make an already-correct result
reproducible. That was measured, by applying the previously-selected base at
`--fuzz=3` and diffing against the new base at `--fuzz=0`:

* `5.17.0` -- the fuzzed result **does not compile**. `5.15`'s
  `mix_pool_bytes()` hunk lands inside `fast_mix()`, and the build stops with
  `'in' undeclared` / `'nbytes' undeclared` at `random.c:915`. This sub-range
  had no base at all before.
* `5.18` -- the fuzzed result compiles, but is **short one site**: the
  opportunistic `try_to_generate_entropy()` test kept calling `crng_ready()`,
  so that path asked the kernel's readiness instead of the module's.
* `5.6`, `5.16`, `6.16` -- the fuzzed result was already byte-identical to the
  new one. These three buy reproducibility rather than a behaviour change: the
  patched tree no longer depends on fuzz landing where it happened to land.

## Naming

    WOLFSSL_KERNELv<version>_FIPS.patch

with `.` replaced by `_`. Two directories carry a distinguishing suffix instead
of their full vendor version string, because the full string is unwieldy:

| directory | patch |
|---|---|
| `5.6`                     | `WOLFSSL_KERNELv5_6_FIPS.patch` |
| `5.10.17`                 | `WOLFSSL_KERNELv5_10_17_FIPS.patch` |
| `5.10.236`                | `WOLFSSL_KERNELv5_10_236_FIPS.patch` |
| `5.14.0-570.58.1.el9_6`   | `WOLFSSL_KERNELv5_14_el9_6_FIPS.patch` |
| `5.15`                    | `WOLFSSL_KERNELv5_15_FIPS.patch` |
| `5.16`                    | `WOLFSSL_KERNELv5_16_FIPS.patch` |
| `5.17`                    | `WOLFSSL_KERNELv5_17_FIPS.patch` |
| `5.17.0`                  | `WOLFSSL_KERNELv5_17_0_FIPS.patch` |
| `5.17.14`                 | `WOLFSSL_KERNELv5_17_14_FIPS.patch` |
| `5.17-ubuntu-jammy-tegra` | `WOLFSSL_KERNELv5_17_tegra_FIPS.patch` |
| `5.18`                    | `WOLFSSL_KERNELv5_18_FIPS.patch` |
| `6.1.73`                  | `WOLFSSL_KERNELv6_1_73_FIPS.patch` |
| `6.12`                    | `WOLFSSL_KERNELv6_12_FIPS.patch` |
| `6.12.75`                 | `WOLFSSL_KERNELv6_12_75_FIPS.patch` |
| `6.15`                    | `WOLFSSL_KERNELv6_15_FIPS.patch` |
| `6.16`                    | `WOLFSSL_KERNELv6_16_FIPS.patch` |
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

**Adding a base changes what the first caller picks, so re-measure it.** Adding
the five newest bases moved that caller's choice for seven of the thirty-four
supported versions: 5.6, 5.16, 5.18, 6.16 and 6.17 moved onto their new exact
base, and 5.7 and 5.8 moved onto `5.6` because it is numerically nearer than
`5.10.17`. The last two were checked rather than assumed -- `5.6` at `--fuzz=3`
produces a byte-identical `random.c` and `random.h` on both trees, because the
only hunk that differs between the two bases is the `random.h` tail and it
fuzzes onto the same anchor. Nothing else moved. A future base can just as
easily move a pick onto something that is *not* equivalent, so measure the
whole matrix when you add one.

Consumers locate a shipped patch by directory and glob (`<version>/*.patch`),
not by filename, so the filenames above are not a harness API.

## Regenerating

`regen-patches.sh` regenerates every patch from full kernel sources staged under
`src/<version>/`, each holding a pristine `random.c.dist` / `random.h.dist`
alongside the modified `random.c` / `random.h`. It is an internal tool: it
requires those staged trees and is not part of the library build.
