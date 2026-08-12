# wolfSSL support for the Altera Agilex 5 SDM (FCS)

This port offloads wolfCrypt operations to the Secure Device Manager (SDM) of
Altera Agilex 5 devices through the FPGA Crypto Services stack: the
`altera_fcs_config` kernel driver and the userspace `libfcs` library
(https://github.com/altera-fpga/libfcs).

The value of the SDM is key isolation, not throughput. Keys created inside the
device never appear in HPS memory, can only be exported in wrapped form, and
are used by handle. For bulk symmetric work the ARMv8 crypto extensions are
faster than the SDM at every size, so the port keeps small operations in
software and offers the device where it adds protection.

## Building

```
./configure --enable-alterafcs \
    CFLAGS="-I<libfcs>/include -I<libfcs>/toolchain/linux_aarch64/include" \
    LDFLAGS="-L<libfcs>/build/lib"
```

`--enable-alterafcs` implies `--enable-cryptocb` and links `-lFCS -lfdt`.
`--enable-alterafcs=rng` builds the RNG support only.

CMake builds use `-DWOLFSSL_ALTERA_FCS=all` (or `rng`). A user-settings
configuration that defines `WOLFSSL_ALTERA_FCS` must still pass that CMake
option so dependency discovery and linkage are selected explicitly.

The port registers itself during `wolfCrypt_Init()` on the device id
`WOLFSSL_ALTERA_FCS_DEVID` (default `0x4143`). Operations reach the SDM when a
context is created on that id:

```c
wc_AesInit(&aes, NULL, WOLFSSL_ALTERA_FCS_DEVID);
wc_InitSha256_ex(&sha, NULL, WOLFSSL_ALTERA_FCS_DEVID);
```

Contexts on any other device id are untouched.

Because one device id covers every algorithm, a deployment that wants only the
operations which gain key isolation can set the automatic mask at build time
and leave hashing and AES on the faster software paths:

```
CFLAGS='-DWOLFSSL_ALTERA_FCS_AUTO_MASK=(WC_ALTERA_FCS_ALGO_ECC|WC_ALTERA_FCS_ALGO_RNG)'
```

This matters for TLS, which propagates its device id to transcript hashes and
AES contexts as well as to keys. The mask cannot be changed after registration
because doing so could strand state or device keys owned by the port.

## Algorithm support

| Algorithm | On the SDM | Notes |
|---|---|---|
| RNG | yes | the TRNG seeds wolfSSL's DRBG; generate requests stay in the DRBG unless built with `WOLFSSL_ALTERA_FCS_RAW_RNG` |
| SHA-256 | yes | messages from `WOLFSSL_ALTERA_FCS_HASH_MIN` (default 4096) through 4 MiB; other sizes complete in software |
| AES-128/256 CBC, CTR | yes | length must be a multiple of 32 bytes and at least `WOLFSSL_ALTERA_FCS_AES_MIN` (default 4096); other requests fall back to software. Device resident keys are supported, see below |
| AES-192 | software | the SDM key object has no 192 bit code |
| AES-GCM | software | not offloaded by this port |
| ECDSA sign | yes | device resident keys only, see below; verify always runs in software |
| ECDH | yes | device resident exchange keys only, see below |
| HMAC generation | software | the SDM cannot generate a MAC |
| HMAC verification | yes | explicit API only, see below |
| HKDF | software | by design, see below |
| SHA-384/512 | software | not offloaded by this port |

Software fallback is automatic and produces identical results; callers do not
need to handle it. The exception is device resident keys, where fallback is
impossible and errors are reported as `WC_HW_E` instead.

## ECC device keys

An SDM key object commits to a usage at creation, and signing and key exchange
are mutually exclusive, so device keys are created through explicit calls
rather than `wc_ecc_make_key_ex()` (which always makes an ordinary software
key, even on the FCS devId):

```c
wc_ecc_init_ex(&key, NULL, WOLFSSL_ALTERA_FCS_DEVID);
wc_AlteraFcsEcc_MakeSigningKey(&key, ECC_SECP256R1);   /* or P-384 */
wc_ecc_sign_hash(hash, hashSz, sig, &sigSz, &rng, &key);
```

```c
wc_AlteraFcsEcc_MakeExchangeKey(&key, ECC_SECP256R1);
wc_ecc_shared_secret(&key, &peerKey, secret, &secretSz);
```

Properties of a device key:

* the private scalar never exists in HPS memory; `wc_ecc_export_private_only`
  fails, and `wc_AlteraFcsEcc_IsDeviceKey()` returns 1
* export through the device yields a wrapped blob, not plaintext
* a signing key refuses ECDH and an exchange key refuses signing, enforced by
  the device
* if the device is unavailable, creation and signing fail with `WC_HW_E`; they
  never degrade to a software key silently

The device holds roughly 27 key slots. `wc_ecc_free()` releases the slot; a
leaked slot lasts until the service session closes.

## AES device keys

An AES key handed to `wc_AesSetKey()` is already plaintext in HPS memory, so
importing it buys SDM usage enforcement, not secrecy. For a key that never
exists outside the device, create it inside the SDM:

```c
wc_AesInit(&aes, NULL, WOLFSSL_ALTERA_FCS_DEVID);
wc_AlteraFcsAes_MakeKey(&aes, 256);                 /* or 128 */
wc_AesSetIV(&aes, iv);
wc_AesCbcEncrypt(&aes, out, in, sz);                /* or CTR */
```

Properties of a resident AES key, mirroring ECC device keys:

* the key never exists in HPS memory: `aes.devKey` and the round key schedule
  stay empty, and `wc_AlteraFcsAes_IsDeviceKey()` returns 1
* `wc_AesSetKey()` on the context is refused with `WC_HW_E`; re-keying means
  freeing the context and creating a new device key
* every operation runs on the device by handle; an SDM-ineligible length or a
  device failure is reported as `WC_HW_E` and never falls back to software,
  because no plaintext key exists to fall back to
* the usage mask is fixed to encrypt/decrypt at creation; 192 bit keys are
  refused because the key object has no code for them
* `wc_AesFree()` releases the device slot

The same 32-byte length multiple and `WOLFSSL_ALTERA_FCS_AES_MIN` floor apply,
but as hard requirements rather than fallback thresholds. Both plaintext data
and ciphertext still pass through HPS memory; the protection is key custody,
not data-path secrecy.

## HMAC verification with vault keys

The SDM verifies MACs under keys the HPS cannot read, but never produces a
MAC, so this ships as its own API rather than behind `wc_Hmac*()`:

```c
word32 keyId;
int ok;
wc_AlteraFcs_HmacImportKey(key, 256, &keyId);   /* or _HmacMakeKey() */
wc_AlteraFcs_HmacVerify(keyId, WC_HASH_TYPE_SHA256, data, dataSz,
                        mac, macSz, &ok);
wc_AlteraFcs_HmacRemoveKey(keyId);
```

Key sizes 256, 384 and 512 bits; digests SHA-256/384/512. Tags produced by any
standard HMAC implementation verify correctly.

## Why HKDF stays in software

`wc_HKDF()` works normally on this platform and always runs in software. This
is deliberate, not a gap:

1. The SDM HKDF command derives a key directly into a device key slot and
   never returns the derived bytes. `wc_HKDF()` exists to hand the caller
   bytes, so the two cannot be connected.
2. The device supports only SHA2-384, while TLS 1.3 and most HKDF callers use
   SHA-256.

This matches the usual division of labor for hardware key stores (TPM,
PKCS#11): long lived identity keys live in the device, session keys are
derived and used in software, because the ciphers that consume them run on the
CPU anyway. A future firmware answer from Altera may enable a derive into
vault helper, which would be a separate API, not `wc_HKDF()`.

## Verifying on hardware

Prerequisites, all outside wolfSSL: a booted Agilex 5 Linux (GSRD or
equivalent) whose kernel includes the `altera_fcs_config` driver, a device
provisioned with an owner root key hash (`quartus_pgm` virtual or physical
fuses; see the Altera Security User Guide), and `libFCS.so` from
https://github.com/altera-fpga/libfcs on the target.

1. Confirm the stack is up: `/sys/kernel/fcs_sysfs` exists and libfcs's
   `fcs_client` can open a session and read random data. If this fails the
   problem is below wolfSSL.
2. Cross compile wolfSSL as shown above, with
   `-DWC_USE_DEVID=0x4143` added to CFLAGS for the test build. When the
   `testwolfcrypt` binary will run on a different machine than it was built
   on, also add `-DUSE_CERT_BUFFERS_2048 -DUSE_CERT_BUFFERS_256
   -DNO_WRITE_TEMP_FILES`: the test otherwise loads its certificates from
   the absolute build tree path baked in at configure time
   (wolfcrypt/test/test_paths.h) and fails its RSA test with a misleading
   "can't open ./certs/client-key.der".
3. Run `./testwolfcrypt` on the target. Expect every test to pass and the
   line `ALTERA-FCS test passed!`, which is the direct exercise of the SDM.
   A failure of only ALTERA-FCS with everything else passing points at the
   device: check provisioning (status 0x85) and session exhaustion (0x84,
   cleared only by a power cycle).
4. Optionally run `./benchmark -aes-cbc -aes-ctr` and confirm the HW rows
   differ from the SW rows, which proves requests are reaching the device.

## Continuous integration coverage

The `Altera Agilex 5 FCS port tests` workflow builds Autotools and CMake
configurations against the interface-only stubs in `tests/altera-fcs-stub`.
The stubs always report unavailable hardware and never implement cryptography.
This lets host CI check feature combinations, linkage, error handling and
software fallback. It does not replace the hardware procedure above, which is
the authoritative test for SDM offload and device resident keys.

## Measured performance

Numbers from a DK-A5E013BM16AEA dev kit (quad Cortex-A55, ARMv8 crypto
extensions), wolfSSL 5.9.2, 1 MB blocks. SW rows are the ARMv8 path, HW rows
are the SDM. The AES-192 HW rows equal the SW rows because 192 bit keys fall
back to software, which doubles as proof the fallback path works.

```
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
AES-128-CBC-enc         SW   805 MiB took 1.003 seconds,  802.604 MiB/s
AES-128-CBC-dec         SW  1480 MiB took 1.002 seconds, 1476.776 MiB/s
AES-256-CBC-enc         SW   620 MiB took 1.003 seconds,  618.076 MiB/s
AES-256-CBC-dec         SW  1240 MiB took 1.002 seconds, 1237.991 MiB/s
AES-128-CBC-enc         HW   100 MiB took 1.045 seconds,   95.691 MiB/s
AES-128-CBC-dec         HW   100 MiB took 1.048 seconds,   95.452 MiB/s
AES-192-CBC-enc         HW   700 MiB took 1.003 seconds,  698.170 MiB/s
AES-256-CBC-enc         HW    95 MiB took 1.044 seconds,   91.039 MiB/s
AES-256-CBC-dec         HW    95 MiB took 1.042 seconds,   91.194 MiB/s
AES-128-CTR             SW  1245 MiB took 1.002 seconds, 1242.926 MiB/s
AES-256-CTR             SW  1135 MiB took 1.002 seconds, 1132.830 MiB/s
AES-128-CTR             HW   105 MiB took 1.045 seconds,  100.463 MiB/s
AES-256-CTR             HW   100 MiB took 1.021 seconds,   97.969 MiB/s
```

Fixed cost operations, measured with device residency asserted:

| Operation | SDM | Software (ARMv8) |
|---|---|---|
| ECDSA P-256 sign | 6.99 ms | 4.28 ms |
| ECDSA P-384 sign | 9.29 ms | 10.87 ms |
| ECDH P-256 shared secret | 7.98 ms | about 1 ms |
| ECDH P-384 shared secret | 8.86 ms | about 3 ms |
| HMAC verify (any digest) | about 9.6 ms | microseconds |
| SHA-256 digest (4 KiB-4 MiB) | about 5 ms + transfer | 592 MiB/s |
| RNG (raw TRNG, opt in) | 0.192 MiB/s | 43.1 MiB/s |

Every operation carries a mailbox round trip of several milliseconds, so the
SDM never beats the CPU except at P-384 signing. The reason to use it is that
the key cannot be read by HPS software, not speed.

## Test output

`testwolfcrypt` built with `--enable-alterafcs` and `-DWC_USE_DEVID=0x4143`
on provisioned hardware. The generic RANDOM, SHA-256, AES-CBC and AES-CTR
tests run against the SDM through the crypto callback; ALTERA-FCS exercises
the device resident ECC keys, ECDH, HMAC verification and the offload
thresholds explicitly. All other tests prove the software paths are
unaffected.

```
SHA-256  test passed!
RANDOM   test passed!
HMAC-SHA256 test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-CBC  test passed!
AES-CTR  test passed!
AES-GCM  test passed!
RSA      test passed!
DH       test passed!
ECC      test passed!
ECC buffer test passed!
ALTERA-FCS test passed!
crypto callback test passed!
Test complete
```

48 tests pass, 0 failures, exit code 0.

## Operational notes

* The SDM grants a single crypto service session per SoC. The port opens it on
  first use, shares it across the process and closes it at exit. A session
  leaked by a crashed process can only be recovered by a power cycle.
* Crypto services require the device to be provisioned with an owner root key
  hash. An unprovisioned device returns SDM status 0x85. Ordinary RNG, hash and
  AES operations fall back to software; device-resident ECC and explicit HMAC
  operations report a hardware error.
* `testwolfcrypt` includes an `ALTERA-FCS` test that exercises every offloaded
  path against the device, including the explicit ECC and HMAC APIs. Building
  the test suite with `-DWC_USE_DEVID=0x4143` additionally routes the generic
  tests through the SDM.
