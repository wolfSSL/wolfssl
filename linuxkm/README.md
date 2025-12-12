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

Build linuxkm with:

```sh
$ ./configure --enable-linuxkm --with-linux-source=/usr/src/linux
$ make -j module
```

note: replace `/usr/src/linux` with a path to your fully configured and built
target kernel source tree.

Assuming you are targeting your native system, install with:

```sh
$ sudo make install
$ sudo modprobe libwolfssl
```

### options

| linuxkm option                   | description                              |
| :------------------------------- | :--------------------------------------- |
| --enable-linuxkm-lkcapi-register | Register wolfcrypt algs with linux kernel <br> crypto API. Options are 'all', 'none', or <br> comma separated list of algs. |
| --enable-linuxkm-pie             | Enable relocatable object build of module|
| --enable-linuxkm-benchmarks      | Run crypto benchmark at module load      |

