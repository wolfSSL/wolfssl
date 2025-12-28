# wolfSSL bsdkm (bsd kernel module)

libwolfssl supports building as a FreeBSD kernel module (`libwolfssl.ko`).
When loaded, wolfCrypt is made available to the rest of the kernel, allowing
other loadable modules to link to wolfCrypt.

Supported features:
- wolfCrypt in kernel.
- FIPS-wolfcrypt.

Planned features:
- crypto acceleration: AES-NI, AVX, etc.
- kernel opencrypto driver registration.
- full wolfSSL in kernel (kernel TLS).

## Building and Installing

Build bsdkm with:

```sh
./configure --enable-freebsdkm --enable-cryptonly && make
```

The default freebsdkm build assumes kernel source tree root at `/usr/src/sys/`.
Use `--with-kernel-source=PATH` to configure a different path.

Assuming you are targeting your native system, install with:

```sh
sudo kldload bsdkm/libwolfssl.ko
```

You should see it now:
```sh
kldstat -m libwolfssl
Id  Refs Name
509    1 libwolfssl
```

Unload with:
```sh
sudo kldunload libwolfssl
```

### options

| freebsdkm option                 | description                              |
| :------------------------------- | :--------------------------------------- |
| --with-bsd-export-syms=LIST      | Export list of symbols as global. <br>. Options are 'all', 'none', or <br> comma separated list of symbols. |
| --with-kernel-source=PATH        | Path to kernel tree root (default `/usr/src/sys`) |

### FIPS

Building with FIPS is largely the same, with the additional step of
configuring a fips hash.

1. Build bsdkm (the `fips_hash` here is a placeholder):

```sh
fips_hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
./configure --enable-freebsdkm --enable-cryptonly --enable-fips=v6 \
  CFLAGS="-DWOLFCRYPT_FIPS_CORE_HASH_VALUE=$fips_hash" && make
```

2. Attempt first install. This is expected to fail, because the hash was a
placeholder.
```sh
$ sudo kldload bsdkm/libwolfssl.ko
Password:
kldload: an error occurred while loading module bsdkm/libwolfssl.ko. Please check dmesg(8) for more details.
```

3. Check dmesg output for the updated hash value (yours will be different).
```sh
$ dmesg | tail -n5
In-core integrity hash check failure.
Rebuild with "WOLFCRYPT_FIPS_CORE_HASH_VALUE=3B144A08F291DBA536324646BBD127447B8F222D29A135780E330351E0DF9F0F".
error: wc_RunAllCast_fips failed at shutdown with return value 19
info: libwolfssl unloaded
module_register_init: MOD_LOAD (libwolfssl_fips, 0xffffffff842c28d0, 0) error 85
```

4. Repeat steps 1-2 with the new hash value. The load should succeed now.

```
$ kldstat -m libwolfssl_fips
Id  Refs Name
523    1 libwolfssl_fips
```

On unload, the FIPS self-test will run a final time and print its status
to system message buffer:

```
info: wolfCrypt FIPS re-self-test succeeded at unload: all algorithms re-verified.
info: libwolfssl unloaded
```

