# wolfSSL linuxkm (linux kernel module)

libwolfssl supports building as a linux kernel module (`libwolfssl.ko`).
When loaded, wolfCrypt and wolfSSL API are made available to the rest of
the kernel, supporting cryptography and TLS in kernel space.

Performing cryptographic operations in kernel space has significant advantages
over user space for high throughput network (VPN, IPsec, MACsec, TLS, etc) and
filesystem (dm-crypt/LUKS, fscrypt disk encryption) IO processing, with the
added benefit that keys can be kept isolated to kernel space. Additionally,
when wolfCrypt-FIPS is used, this provides a simple recipe for FIPS-compliant
kernels.

Supported features:

- crypto acceleration: AES-NI, AVX, etc.
- kernel crypto API registration (wolfCrypt algs appear as drivers in `/proc/crypto`.).
- `CONFIG_CRYPTO_FIPS`, and crypto-manager self-tests.
- FIPS-compliant patches to `drivers/char/random.c`, covering 34 kernel
  versions from 5.6 through 7.1, **excluding `PREEMPT_RT`** (see below).  Every
  supported version maps to a base patch that applies at `--fuzz=0`; see
  `patches/README.md` for the full version-to-patch table.  If your version is
  not listed there, it is not covered -- do not assume a nearby base will
  apply, because a fuzzed hunk can land in the wrong function and still report
  success.
- Supports FIPS-compliant WireGuard (https://github.com/wolfssl/wolfguard).
- TLS 1.3 and DTLS 1.3 kernel offload.

### `PREEMPT_RT` kernels are out of scope

The kernel range above is a range of **non-`PREEMPT_RT`** releases.  No
`PREEMPT_RT` kernel is a tested operating environment for this module.

`PREEMPT_RT` changes one thing that matters here: `spinlock_t` becomes a
sleeping `rt_mutex` (`Documentation/locking/locktypes.rst`), so this module's
`wolfSSL_Mutex` -- `spin_lock_bh()`, see `linuxkm_wc_port.h` -- becomes a lock
that can block, and taking one inside an open `SAVE_VECTOR_REGISTERS()`
section becomes scheduling while atomic.

The module refuses that shape rather than relying on the kernel configuration
to prevent it.  `wc_lkm_LockMutex()` in `module_hooks.c` returns
`BAD_STATE_E` and warns whenever `wc_linuxkm_in_svr_bracket()` is true; the
test is keyed on this module's own bracket depth, not on `preempt_count()`, so
it fires on non-`RT` kernels too and is exercised by every test environment.
Every `wc_LockMutex()` call in a kernel build reaches it.

What has not been done is the other half: no `PREEMPT_RT` kernel has been run
to the point of exercising an `RT`-specific path, and the `CONFIG_PREEMPT_RT`
arms of `spin_lock_bh()` here and of `WC_SVR_PIN_CPU()` in
`x86_vector_register_glue.c` have never been compiled.  Until that changes,
`PREEMPT_RT` is unclaimed.

## Kernel configuration prerequisites

`libwolfssl.ko` registers with the kernel crypto API, so the API's own
registration symbols must be resolvable at `insmod` time.

**On 7.1 and later, `CRYPTO_AEAD`, `CRYPTO_RNG` and `CRYPTO_KPP` must be built
in (`=y`), not modular.** Through 7.0.14 these land in `vmlinux` regardless of
how they are configured, so the requirement is invisible. From 7.1.9 they can
land in `crypto/aead.ko` instead, and `insmod libwolfssl.ko` then fails with:

```
libwolfssl: Unknown symbol crypto_register_aead (err -2)
```

This is a kernel-configuration prerequisite, not a module defect: the module is
asking for a symbol the running kernel did not export. Set the three options to
`y` in the kernel `.config` before building the kernel for any 7.1 or later
operational environment.

## Building and Installing

Build `libwolfssl.ko` with:

```sh
$ ./configure --enable-linuxkm --with-linux-source=/usr/src/linux
$ make -j module
```

Note: Replace `/usr/src/linux` with a path to your fully configured and built
target kernel source tree.

If building from a FIPS kernel module bundle, build `libwolfssl.ko` with:
```sh
$ ./configure --enable-fips=fips_flavor --enable-linuxkm --with-linux-source=/usr/src/linux
$ make -j module-with-matching-fips-hash
```

Note: Replace `fips_flavor` with the correct value.

Assuming you are targeting your native system, install with:

```sh
$ sudo make install
$ sudo modprobe libwolfssl
```

### Key additional Linux kernel module configuration options

| option                             | description                              |
| :------------------------------- | :----------------------------------------- |
| `--enable-linuxkm-lkcapi-register` | Register wolfcrypt algs with linux kernel crypto API. <br> Optional value is 'all', 'all-kconfig', 'none', or a comma separated list of algs. |
| `--enable-all-crypto`              | Enable extra crypto algorithms           |
| `--enable-intelasm`                | x86/amd64 crypto acceleration            |
| `--enable-cryptonly`               | Omit TLS/DTLS implementation (normally recommended) |

### Enabling DTLS 1.3 in the kernel module

`--enable-linuxkm` does not implicitly enable TLS 1.3 or DTLS, so the DTLS 1.3
configure check (`configure.ac:5634-5636`) requires all three flags to be
passed explicitly:

```sh
./configure --enable-linuxkm \
            --enable-tls13 --enable-dtls --enable-dtls13 \
            --with-linux-source=/lib/modules/$(uname -r)/build
make -j$(nproc) module
```

The resulting `linuxkm/libwolfssl.ko` exports the DTLS 1.3 entry points
(`wolfDTLSv1_3_client_method`, `wolfDTLSv1_3_server_method`, etc.) as GPL
kernel symbols, available to other in-kernel consumers via
`EXPORT_SYMBOL_GPL`.

### Additional configuration options for verification, performance evaluation, and troubleshooting

| option                             | description                              |
| :------------------------------- | :----------------------------------------- |
| `--enable-crypttests`              | Run `wolfcrypt_test()` at module load (not recommended for production) |
| `--enable-kernel-benchmarks`       | Run crypto benchmark at module load (_not appropriate for production_) |
| `--enable-kernel-verbose-debug`    | Extra runtime diagnostic and informational messages |
| `--enable-kernel-stack-debug`      | Report stack usage during module startup |
| `--enable-debug-trace-errcodes`    | Profuse debug logging (_not appropriate for production_) |
| `--enable-debug-trace-errcodes=backtrace` | Even more profuse debug logging (_not appropriate for production_) |


## Kernel Patches

The `linuxkm/patches` directory in the source distribution contains a patch to the linux kernel CRNG. The
CRNG provides the implementation for `/dev/random`, `/dev/urandom`, and
`getrandom()`, and for internal RNG APIs such as `get_random_bytes()`,
`get_random_u32()`, etc.

The patch applies to these two sources:

- `drivers/char/random.c`
- `include/linux/random.h`

It adds a callback facility to the core kernel code that allows `libwolfssl.ko`
to register FIPS-compliant algorithms in place of the native implementation
(which is based on non-FIPS ChaCha20 and blake2s algorithms).  When `libwolfssl.ko` is configured with
`--enable-linuxkm-lkcapi-register` and loaded into a patched kernel, it
automatically registers the FIPS callbacks.  At startup, the module will report

```
libwolfssl: kernel global random_bytes handlers installed.
```

Additionally, `/proc/crypto` will advertise that the FIPS DRBG is installed at
highest priority, with "-wolfentropy" and/or "-rdseed", and "-with-global-replace":
```ini
name         : stdrng
driver       : sha2-256-drbg-nopr-wolfentropy-wolfcrypt-fips-140-3-with-global-replace
module       : libwolfssl
priority     : 100000
refcnt       : 2
selftest     : passed
internal     : no
fips         : yes
type         : rng
seedsize     : 0
```


Patches are provided for thirty-four kernel versions, 5.6 through 7.1, with the
most recent patchset tested nightly with the latest Linux release and RC
kernels, and with the latest linux-next snapshot.

**Look your version up in `patches/README.md`; do not pick by version number.**
The directories under `patches/` are *bases*, not the list of what is
supported, and the mapping from version to base is neither one-to-one nor
nearest-by-number.  `drivers/char/random.c` was rewritten in 5.18 and the
rewrite was then backported into the LTS branches and not into the others, so
5.10 is newer in API shape than 5.13 and 5.15 is newer than 5.16.  Two series
change shape mid-series as well.  Picking the nearest base by number lands you
on the wrong side of one of those seams, where a hunk can still apply -- with
fuzz -- into the wrong function and leave a tree that will not build.

The coverage table in `patches/README.md` was produced by applying every base
to every supported version at `--fuzz=0`, so it says which patch to use and it
is derived from measurement rather than arithmetic.

### Patch procedure

1. Verify that the patchset applies cleanly, using a dry run.  Use `--fuzz=0`:
   the default fuzz of 2 drops context lines until a hunk matches *something*,
   so a hunk can land in the wrong function and still be reported as applied.


```console
$ cd ~/kernelsrc/
$ patch -p1 --dry-run --fuzz=0 < ~/wolfssl-5.8.2/linuxkm/patches/6.12/WOLFSSL_KERNELv6_12_FIPS.patch
checking file drivers/char/random.c
checking file include/linux/random.h
```

2. Optionally, clean the kernel src tree before patching:

```console
$ make mrproper
```

3. Patch the kernel:

```console
$ patch -p1 --fuzz=0 < ~/wolfssl-5.8.2/linuxkm/patches/6.12/WOLFSSL_KERNELv6_12_FIPS.patch
patching file drivers/char/random.c
patching file include/linux/random.h
```

4. Build and optionally install the patched kernel:
```console
$ make -j
# make modules_install
# make install
```

5. Build `libwolfssl.ko` with `--enable-linuxkm-rbgc`.  **Both halves are
   required.** The patch on its own changes nothing: with no module registered,
   `drivers/char/random.c` behaves exactly as it did before, and a module built
   without `--enable-linuxkm-rbgc` registers nothing.  A patched kernel plus a
   default-configured module is a kernel serving its own randomness, and
   nothing says so.

### What happens if the kernel is NOT patched

Measured on 6.6.99, x86_64, at the code-freeze candidate:

| you do this | what happens |
|---|---|
| build `libwolfssl.ko` **without** `--enable-linuxkm-rbgc` | builds and `insmod`s normally.  `get_random_bytes()` stays with the kernel; the module never claimed it, and registers nothing. |
| `./configure --enable-linuxkm-rbgc` against unpatched kernel source | **`configure` succeeds.** It does not check the kernel source, so there is no diagnostic at this step. |
| `make module` after that configure | **fails**, on `linuxkm/module_hooks.c`: `#error LINUXKM_RBGC requires a kernel carrying one of the patches in linuxkm/patches/.` |
| `insmod` an RBGC `libwolfssl.ko` that was built against a *patched* tree, on an *unpatched* kernel of the same version | **refuses to load**: `libwolfssl: Unknown symbol wolfssl_linuxkm_register_random_bytes_handlers (err -2)`.  Nothing is registered and no wolfCrypt driver appears in `/proc/crypto`.  The vermagic matches, so the symbol check is the whole defence -- and it holds. |

There is no configuration in which an unpatched kernel silently ends up with a
half-installed hook.  Either the build stops, or the load stops, or the module
runs without ever claiming `get_random_bytes()`.
