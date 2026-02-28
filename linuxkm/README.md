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
- FIPS-compliant patches to `drivers/char/random.c`, covering kernels 5.10 to
  6.15.
- Supports FIPS-compliant WireGuard (https://github.com/wolfssl/wolfguard).
- TLS 1.3 and DTLS 1.3 kernel offload.

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


Patches are provided for several kernel versions, ranging from `5.10.x` to
`6.15`, with the most recent patchset tested nightly with the latest Linux
release and RC kernels, and with the latest linux-next snapshot.  Use the
patchset with the most recent target kernel version not greater than that of the
kernel you're targeting.

### Patch procedure

1. Verify that the patcheset applies cleanly, using a dry run:

```console
$ cd ~/kernelsrc/
$ patch -p1 --dry-run  < ~/wolfssl-5.8.2/linuxkm/patches/6.12/WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS-6v12.patch
checking file drivers/char/random.c
checking file include/linux/random.h
```

2. Optionally, clean the kernel src tree before patching:

```console
$ make mrproper
```

3. Patch the kernel:

```console
$ patch -p1 < ~/wolfssl-5.8.2/linuxkm/patches/6.12/WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS-6v12.patch
patching file drivers/char/random.c
patching file include/linux/random.h
```

4. Build and optionally install the patched kernel:
```console
$ make -j
# make modules_install
# make install
```
