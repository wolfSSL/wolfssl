# Cross-library compile testing

Compile tests the wolfSSL product family (wolfSSH, wolfCLU, wolfTPM, wolfMQTT,
wolfPKCS11, wolfProvider) against **this** wolfSSL, so a wolfSSL change that
would stop a downstream product from *compiling* is caught in CI.

**Compile only. There is no runtime testing here** (the product scripts run
`make`, never `make check`). Each product is built twice: at the HEAD of its
default branch and at its latest tagged release.

> Note: the workflow `.yml` files (the reusable engine `cross-library.yml` and
> the per-product `cross-<product>.yml` callers) live in `.github/workflows/`
> itself, because GitHub only discovers workflows directly in that directory,
> not in subfolders. Everything else (these scripts) lives here.

## Layout

```
.github/workflows/
  cross-library.yml          # reusable engine (on: workflow_call)
  cross-<product>.yml         # one thin caller per product (matrix: head, latest)
  cross-library/
    README.md                 # this file
    scripts/                  # all the machinery
```

## How a run works (per product, per ref)

The engine (`cross-library.yml`) runs one job in a clean container
(`ubuntu:24.04` by default; a caller may pass `debian:13`):

1. **Install build tools** with `apt-get` (`+ apt_packages` from the caller).
2. **Checkout wolfSSL** (full history + tags, for the break check below).
3. **`build-wolfssl.sh`** builds this checkout's wolfSSL with the product's
   required `wolfssl_configure` flags and installs it to a local dir.
4. **`resolve-ref.sh`** resolves the ref to build: the highest version tag
   (`ref_mode: latest`) or the default branch (`ref_mode: head`).
5. **`<product>.sh`** clones the product at that ref and compiles it against the
   installed wolfSSL (`--with-wolfssl=<install dir>`).
6. If the compile fails, **`check-break.sh`** decides whether it was a
   *declared* break (allowed, tracked) or an *undeclared* one (job fails). See
   below.

## Scripts

| Script | Role |
|---|---|
| `build-wolfssl.sh <src> <install> <configure>` | Build and install wolfSSL from `<src>`. Configure flags are one `eval`-ed string so a quoted `CFLAGS=`/`C_EXTRA_FLAGS=` group survives. |
| `common.sh` | Shared helpers: `resolve_repo_url`, `default_branch` (master/main auto-detect), `latest_tag`, and `cross_build_autotools` (clone, configure `--with-wolfssl` plus `-I`/`-L`/rpath/`PKG_CONFIG_PATH`, then `make`). |
| `resolve-ref.sh <repo> <mode>` | Echo the ref for `head` (default branch) or `latest` (highest tag). |
| `latest-tag.sh <repo>` | Poll the highest version tag (`git ls-remote --sort=-v:refname`, robust to mixed tag styles). |
| `check-break.sh <product> <ref>` | Break declaration check (see below). |
| `<product>.sh [-t <ref>] <install> <repo> [product_configure...]` | Per-product build. Most just call `cross_build_autotools`; `wolfprovider.sh` also passes `--with-openssl`. |

## Break declarations

Testing a product's last *release* against wolfSSL HEAD can legitimately fail
when wolfSSL intentionally changes an API. This applies **only to the `latest`
(release-tag) leg**. To keep such a break honest and auditable, it must be
**declared in a wolfSSL commit message** with a token naming the **exact release
tag**:

```
breaks-<product>=<tag>      e.g.  breaks-wolfssh=v1.5.0-stable
```

There is **no `latest`/`head`/`*` shorthand**. The broken release must be named
explicitly, so every newly-broken release needs its own fresh, reviewable
declaration (an old token simply stops matching once the tag moves on).

**A `head` (master) break is never declarable.** If a product's default branch
stops compiling against wolfSSL master, there is no token to wave it through.
The PR must be reworked, or a fix put up on the product's master. A token whose
value is `head`, `master`, `main`, or `*` is ignored outright.

`check-break.sh` scans wolfSSL commits for a matching token (case-insensitive)
over a window of the **last two wolfSSL release cycles**, from the
*second-newest* `v*-stable` release tag to HEAD. Two cycles (not one) so that
when wolfSSL cuts a new release, a break declared in the prior cycle keeps being
honored for one more cycle, giving the downstream product time to ship a fixed
release before PRs go red again for the same known issue. (Release tags are
picked by version order, not commit ancestry, so wolfSSL's many non-release tags
like `*-CHKIN` are ignored.) Then the engine:

| Compile | Declared? | Result |
|---|---|---|
| passes | no | green |
| passes | yes | green, plus a warning to remove the now-stale token |
| fails | yes | green, plus a warning "known/tracked break" (shows the commit) |
| fails | no | red. Fix it, or add a `breaks-<product>=<tag>` token |

Because the token names the exact tag, it automatically stops matching once the
product releases a newer tag, forcing a fresh, explicit declaration if the new
release is still broken.

The failure message depends on which leg broke:

- **`latest` (a released tag)**: the tag is immutable, so the job explains the
  `breaks-<product>=<tag>` mechanism and asks you to either declare the break
  (to track it and go green) or rework the change so the release still builds.
- **`head` (the product's default branch)**: this is expected to track wolfSSL
  and is **never waivable**. The job fails and asks you to **rework the PR or put
  up a fix on the product's master branch**. There is no break declaration for a
  head failure.

## Adding a product

1. Copy an existing `cross-<product>.yml` caller and set `product`, `repo`,
   `wolfssl_configure` (the wolfSSL flags that product documents), optional
   `product_configure`, `script`, and optional `apt_packages`.
2. Add a `scripts/<product>.sh`. If it is a standard autotools project, it is
   just:
   ```sh
   #!/usr/bin/env bash
   DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
   . "$DIR/common.sh"
   cross_build_autotools "$@"
   ```
   Non-autotools products (see `wolfprovider.sh`) can `_prepare "$@"` and then
   run their own build steps.

Get each product's required `wolfssl_configure` from that product's own
README or CI, not by guessing. The flags matter (e.g. wolfPKCS11 and
wolfProvider need specific `C_EXTRA_FLAGS`/`CFLAGS` defines).
