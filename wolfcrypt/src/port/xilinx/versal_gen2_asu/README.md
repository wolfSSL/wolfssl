# wolfSSL port for the Versal Gen 2 ASU

Routes wolfCrypt operations to the ASU (Application Security Unit) on Versal
Gen 2 parts. The port registers a wolfSSL crypto callback device; anything the
ASU cannot do falls back to software, so a build with the port on still passes
the full wolfCrypt self-test.

## Turning it on

Define this in `user_settings.h`:

```c
#define WOLFSSL_VERSAL_GEN2_ASU
```

That is the whole setup for everything except ECIES. `wolfCrypt_Init()`
registers the device and brings the ASU client up, so an application needs no
ASU calls of its own:

```c
ret = wolfCrypt_Init();     /* opens the mailbox, calls XAsu_ClientInit */
```

ECIES is the one exception: it uses its own context's device id, which the
application has to set. See "What ECIES needs to reach the ASU" below.

The BSP must have the `xilasu` and `xilmailbox` libraries enabled.

## What runs on hardware

| Engine | Covered |
| --- | --- |
| Hash | SHA2-256/384/512, SHA3-256/384/512, SHAKE256 |
| HMAC | over SHA2-256/384/512 and SHA3-256/384/512 |
| AES | CBC, ECB, CTR, CFB, OFB, GCM, CCM |
| CMAC | AES-CMAC |
| RSA | raw modexp, plus PSS and OAEP padding when `WOLF_CRYPTO_CB_RSA_PAD` is set |
| ECDSA | NIST P-192/256/384, Brainpool P-256/320/384/512 |
| EdDSA | plain Ed25519 and Ed448 sign and verify |
| ECDH | the same curves as ECDSA |
| X25519 / X448 | key agreement, Vitis 2026.1 and later |
| ECIES | AES-GCM with HKDF-SHA256; needs a context device id, see below |
| TRNG | seed and random block |

Anything outside this list is declined and wolfSSL runs it in software. That
includes AES-192, partial AES blocks, SHA-512/224 and 512/256, Keccak padding,
SHAKE128 and deterministic ECDSA. The older ECIES layouts are different: the
port is not built at all, see below.

## Settings

`WOLFSSL_VERSAL_GEN2_ASU` on its own offloads every engine above. Name one or
more of these instead and only those are offloaded:

```
WOLFSSL_VERSAL_GEN2_ASU_TRNG      WOLFSSL_VERSAL_GEN2_ASU_CMAC
WOLFSSL_VERSAL_GEN2_ASU_HASH      WOLFSSL_VERSAL_GEN2_ASU_RSA
WOLFSSL_VERSAL_GEN2_ASU_HMAC      WOLFSSL_VERSAL_GEN2_ASU_ECC
WOLFSSL_VERSAL_GEN2_ASU_CIPHER
```

`_ECC` also covers ECDH, ECIES, Ed25519 and Ed448 when those features are
built.

Ed25519 and Ed448 offload needs classic ECC turned on as well, because the
EdDSA handlers live in the same file as ECDSA and that file is built only when
`HAVE_ECC` is set. A build with EdDSA but no classic ECC still works, it just
runs EdDSA in software.

Other switches:

| Macro | Effect |
| --- | --- |
| `WOLFSSL_VERSAL_GEN2_ASU_DEVID` | device id for the callback, default `0x4153` |
| `WOLFSSL_VERSAL_GEN2_ASU_IPI_BASEADDR` | IPI channel, default `XPAR_XIPIPSU_0_BASEADDR` |
| `WOLFSSL_VERSAL_GEN2_ASU_NO_CLIENT_INIT` | the application calls `XAsu_ClientInit` itself |
| `WOLFSSL_VERSAL_GEN2_ASU_NO_RSA_PAD` | RSA on, padding in software |
| `WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1` | the BSP has Vitis 2026.1 xilasu |
| `WOLFSSL_VERSAL_GEN2_ASU_NO_ECC_P521` | drop P-521, which 2026.1 offloads |
| `WOLFSSL_VERSAL_GEN2_ASU_NO_X25519` | drop X25519, which 2026.1 offloads |
| `WOLFSSL_VERSAL_GEN2_ASU_NO_X448` | drop X448, which 2026.1 offloads |
| `WOLFSSL_VERSAL_GEN2_ASU_DEBUG` | print every ASU operation over the UART |
| `WOLFSSL_VERSAL_GEN2_ASU_RTC` | supply the benchmark time source from the port |
| `XASU_DISABLE_CACHE` | cache is off, so skip all buffer flush and reload work |

The port sets `WOLF_CRYPTO_CB`, `WOLF_CRYPTO_CB_CMD`, `WOLF_CRYPTO_CB_COPY` and
`WOLF_CRYPTO_CB_FREE` for you, and points `WC_USE_DEVID` at the ASU device so
the unmodified wolfCrypt test and benchmark route through it. `WC_USE_DEVID`
lands on keys and crypto objects at init; ECIES does not read it from there, so
the test and benchmark hand it to each ECIES context themselves.

## Which Vitis release

The xilasu client API changed in Vitis 2026.1: the operation flags became
generic, several request structures moved their key fields into key objects,
and RSA gained an output length. The port builds against either release, but it
cannot tell them apart on its own, so name the one the BSP was built with:

```c
#define WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1
```

2025.2 is assumed when neither that nor `..._XILASU_2025_2` is named, so an
existing build keeps working untouched. Naming the wrong one stops the build
with a message rather than failing later.

2026.1 also brings work the older release could not offload at all: P-521,
X25519 and X448, RSA OAEP decrypt, SHAKE output past 64 bytes, and CCM on data
that is not a whole number of blocks. Each turns on by itself there.

The X25519 and X448 offload reads the scalar and the peer point out of the
wolfSSL key, so it needs the curve key export APIs. Naming
`NO_CURVE25519_KEY_EXPORT` or `NO_CURVE448_KEY_EXPORT` alongside it stops the
build with a message from `asu_ecdh.c` rather than failing at link: drop
the macro, or turn the offload off with `WOLFSSL_VERSAL_GEN2_ASU_NO_X25519` /
`..._NO_X448`.

## Known limits

**P-521 needs Vitis 2026.1 firmware.** The client still caps the digest at 64
bytes, short of the 66 P-521 uses, so the firmware has to front-pad it. 2026.1
does, and `WOLFSSL_VERSAL_GEN2_ASU_ECC_P521` turns on there by itself for both
ECDSA and ECDH; `WOLFSSL_VERSAL_GEN2_ASU_NO_ECC_P521` opts back out. Earlier
firmware padded it wrong, so the curve stays in software on 2025.2.

**CCM block alignment is a 2025.2 limit.** That AES-CCM engine only took data
and AAD in whole 16-byte blocks, so
`WOLFSSL_VERSAL_GEN2_ASU_CCM_ALIGN_DECLINE` sends anything else to software -
the RFC 3610 vectors in the wolfCrypt self-test among them. 2026.1 accepts
unaligned lengths, so leave the macro undefined there and keep the work on
hardware.

The benchmark trips over the same limit. It authenticates `AES_AUTH_ADD_SZ`
bytes of extra data, which defaults to 13, so on 2025.2 every AES-CCM row
declines to software however long the message is. Build the benchmark with
`AES_AUTH_ADD_SZ` set to 16 to keep those rows on hardware; wolfSSL already
does that for the first-generation Versal port for the same reason.

**ECIES needs its own device id on the context.** A device id on the ECC key
does not count for ECIES; without `wc_ecc_ctx_set_dev_id` it runs in software
and gives no warning (with `WOLF_CRYPTO_CB_FIND` the finder still applies). See
below.

**ECIES needs the KDF context path.** See below.

**ECIES needs `WOLFSSL_ECIES_GEN_IV`, and only offloads one direction.** See
below.

## ECIES on hardware

The ASU runs ECIES as one command: ECDH, then HKDF, then AES-GCM. It has no
input for extra authenticated data, so the context has to be keyed in the way
that leaves the MAC salt empty.

Use `wc_ecc_ctx_set_kdf_salt`, not `wc_ecc_ctx_set_peer_salt`:

```c
ecEncCtx* ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);

/* Required: ECIES uses the context's device, not the key's. */
wc_ecc_ctx_set_dev_id(ctx, WOLFSSL_VERSAL_GEN2_ASU_DEVID);

wc_ecc_ctx_set_algo(ctx, ecAES_256_GCM, ecHKDF_SHA256, ecHMAC_SHA256);
wc_ecc_ctx_set_kdf_salt(ctx, salt, saltSz);
wc_ecc_ctx_set_info(ctx, info, infoSz);

wc_ecc_encrypt(privKey, peerPubKey, msg, msgSz, out, &outSz, ctx);
```

The other side does the same with `REQ_RESP_SERVER` and the same salt and
context bytes, then calls `wc_ecc_decrypt`.

The wolfCrypt benchmark keys ECIES the other way by default, so its ECIES rows
run in software. Build the benchmark with `WC_BENCH_ECIES_KDF` to add a second
set of rows, tagged `-kdf`, that use the context shown above and reach the ASU.
The benchmark sets the context device id itself on its `-dev` rows.

What the offload requires:

| Setting | Value |
| --- | --- |
| Build | `WOLFSSL_ECIES_GEN_IV`, with neither `WOLFSSL_ECIES_OLD` nor `WOLFSSL_ECIES_ISO18033` |
| Device | `wc_ecc_ctx_set_dev_id` on the context; the key's devId is not used |
| RNG | one on the key or on the context, see below |
| Scheme | `ecAES_128_GCM` or `ecAES_256_GCM` with `ecHKDF_SHA256` |
| KDF salt | `wc_ecc_ctx_set_kdf_salt`, passed through as given |
| KDF context | `wc_ecc_ctx_set_info`, must not be empty |
| MAC salt | must be empty, so no `wc_ecc_ctx_set_peer_salt` |
| Protocol | `REQ_RESP_CLIENT` to encrypt, `REQ_RESP_SERVER` to decrypt |
| Curves | P-192, P-256, P-384, Brainpool P-256, P-320, P-384, P-512 |

`wc_ecc_ctx_set_peer_salt` is the usual wolfSSL way to key ECIES, and it sets a
MAC salt as a side effect. wolfSSL feeds that salt to AES-GCM as extra
authenticated data, which the ASU cannot accept, so the port declines and
wolfSSL runs ECIES in software. There is no way around this from the port.

Declining is not the same as running with no hardware. The software ECIES path
still passes the context's device id to the AES and to the MAC HMAC underneath,
so those operations go to the ASU one at a time. Only the single-command ECIES
is lost.

It helps to be exact about which pieces reach the ASU on that path, because
they use two different device ids:

| Stage | Uses | On the ASU? |
| --- | --- | --- |
| ECDH shared secret | the key's devId | yes, via `asu_ecdh.c` |
| HKDF-SHA256 KDF | none, always software | no |
| AES-GCM / AES-CBC DEM | the context devId | yes, via `asu_cipher.c` |
| MAC HMAC | the context devId | yes, via `asu_hmac.c` |

The ECDH, cipher and MAC need their device id set to reach the ASU, and the
ECDH uses a different id from the other two. So a context with no device id
does not mean "no hardware": the ECDH still lands on the ASU whenever the key
carries the device id, while the cipher and MAC fall back to software.

The KDF step always runs in software whatever is set. It hands ECIES
temporaries to the callback and ECIES cannot wait for a pending result, so it
is never offloaded on this path.

**The private key passed to encrypt is not used.** `wc_ecc_encrypt` takes a
private key, and software derives the shared secret from it and puts its public
point in the output. The ASU cannot be given that scalar: it generates its own
ephemeral key pair inside the single ECIES command and returns that public key
in the output instead. The peer decrypts against the returned key, so the
exchange works and matches software on the wire, but the key you passed in does
not appear in the result. Decrypt is not affected, and uses the private key you
supply.

## What ECIES needs to reach the ASU

Three things on top of the table above.

**The context must carry the device id.** `wc_ecc_ctx_set_dev_id(ctx,
WOLFSSL_VERSAL_GEN2_ASU_DEVID)`, on every context, in both directions. ECIES
takes its device from the context and never from the ECC key, so a key opened
with `wc_ecc_init_ex(&key, heap, WOLFSSL_VERSAL_GEN2_ASU_DEVID)` is not enough
on its own. Miss it and ECIES still works, in software, with no warning,
unless a `WOLF_CRYPTO_CB_FIND` finder routes it to a device.

**The build must use `WOLFSSL_ECIES_GEN_IV`.** The ASU puts the GCM nonce in
the message, which is what that mode does. `WOLFSSL_ECIES_OLD` and
`WOLFSSL_ECIES_ISO18033` keep the nonce elsewhere, so in those modes the port
is not built at all and wolfSSL never calls it.

**Only one direction offloads.** Client and server each use their own half of
the derived key. The ASU always uses the first half, which is the half the
client encrypts with and the server decrypts with. So a client encrypting, or
a server decrypting, runs on hardware. The reply going back uses the second
half and runs in software.

Encrypt needs an RNG, on the key or on the context, or it returns
`MISSING_RNG_E`. Decrypt does not, since the nonce arrives in the message.

## Files

```
asu_cryptocb.c   device registration and the callback dispatcher
asu_util.c       client bring-up, waiting, cache handling, timer
asu_hash.c       SHA2, SHA3, SHAKE256
asu_hmac.c       HMAC
asu_cipher.c     AES
asu_cmac.c       AES-CMAC
asu_rsa.c        RSA
asu_ecc.c        ECDSA, Ed25519, Ed448
asu_ecdh.c       ECDH, X25519, X448
asu_ecies.c      ECIES
asu_rng.c        TRNG
```

Headers live in `wolfssl/wolfcrypt/port/xilinx/versal_gen2_asu/`, with the
build settings in `asu_settings.h`.
