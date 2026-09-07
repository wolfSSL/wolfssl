# wolfHAL port

Routes wolfCrypt AES (ECB/CBC/GCM/CCM) and RNG to a board's hardware through
[wolfHAL](https://github.com/wolfSSL/wolfHAL) and the wolfSSL crypto callback
framework. Anything the hardware does not cover returns `CRYPTOCB_UNAVAILABLE`
and falls back to software.

## Building

```sh
./configure --with-wolfhal=/path/to/wolfHAL \
            --with-wolfhal-board=/path/to/your/board
make
```

`--with-wolfhal` points at the wolfHAL source tree; `--with-wolfhal-board`
points at the directory holding your `wolfHAL_board.h`. The port forces a
static-only build: wolfHAL's objects are compiled by your application, so
`libwolfssl.a` is left with unresolved `whal_*` references for your final link
to satisfy. That also means wolfSSL's bundled examples and crypt tests are
disabled.

## wolfHAL_board.h

`wolfHAL_board.h` is yours, not wolfSSL's, the same arrangement `settings.h` has
with `user_settings.h`. Both wolfHAL and wolfSSL find it by quoted include off
your `-I` path:

* wolfHAL's driver TUs (`src/crypto/stm32wb_aes.c`, `src/rng/stm32wb_rng.c`)
  expand the `WHAL_CFG_*_DEV` initializers in it to define their device
  singletons.
* wolfSSL's `wolfhal.c` reads it for the wolfHAL platform driver headers and
  for one device macro per algorithm:
  `WC_WOLFHAL_AES_{ECB,CBC,GCM,CCM}_DEV` and `WC_WOLFHAL_RNG_DEV`. The
  `BOARD_AES_*_DEV` / `BOARD_RNG_DEV` names a stock `wolfHAL_board.h` already
  uses are accepted directly, so an in-tree wolfHAL board needs no additions.

Only the modes `wolfHAL_board.h` names a device for are offloaded. A mode
wolfSSL is built with but `wolfHAL_board.h` does not name is left to wolfCrypt's
software implementation, so hardware that covers, say, only GCM needs just
`WC_WOLFHAL_AES_GCM_DEV`, and a build with CBC enabled still links and runs.

`WC_WOLFHAL_RNG_DEV` is the exception. The board's TRNG is the only entropy
source available, so there is nothing to decline to and defining
`WOLFSSL_WOLFHAL_RNG` without a device is a build error.

Because the `BOARD_*_DEV` names are accepted, a stock `wolfHAL_board.h` from
wolfHAL's `boards/` directory works as-is:

```sh
./configure --with-wolfhal=../wolfHAL \
            --with-wolfhal-board=../wolfHAL/boards/stm32wb55xx_nucleo
```

Use one of those as the starting point for a board wolfHAL does not already
cover.

## Error contract

`wolfhal.c` translates wolfHAL status codes into wolfCrypt errors:

| wolfHAL | wolfCrypt | Effect |
|---|---|---|
| `WHAL_SUCCESS` | `0` | hardware handled the operation |
| `WHAL_ENOTSUP` | `CRYPTOCB_UNAVAILABLE` | falls back to software |
| `WHAL_EINVAL` | `BAD_FUNC_ARG` | fatal, returned to the caller |
| `WHAL_EHARDWARE` | `WC_HW_E` | fatal |
| `WHAL_ETIMEOUT` | `WC_TIMEOUT_E` | fatal |
| anything else | `WC_HW_E` | fatal |

When the wolfHAL driver returns `WHAL_ENOTSUP`, the arguments were valid but
the hardware itself cannot support the operation. As such it will fall back to
software implemented crypto.

`wolfHAL_board.h` gates whole modes, so this matters for what it cannot gate. An
AES engine limited to 128-bit keys must answer a 256-bit request with
`WHAL_ENOTSUP`, not `WHAL_EINVAL`, or the handshake fails instead of falling
back to software.

## Runtime

`wolfCrypt_Init()` registers the device at `WOLFSSL_WOLFHAL_DEVID` (default
`0x5748`), and `wolfhal_settings.h` maps `WC_USE_DEVID` to it so unmodified
wolfCrypt callers route through the hardware. Call `whal_Board_Init()`, which
brings up the peripherals, *before* `wolfCrypt_Init()`. To register at a
different or additional devId, call `wc_wolfHAL_RegisterDevice()` yourself.

Setting either devId macro alone makes the other follow it, so the two cannot
silently diverge. Setting both to different values is the multi-device case:
wolfHAL registers at `WOLFSSL_WOLFHAL_DEVID`, unqualified callers reach
`WC_USE_DEVID`.

Define `WOLFSSL_WOLFHAL_RNG` to draw entropy from the board's TRNG. Nothing
else is needed: `wolfhal_settings.h` wires `wc_wolfHAL_GenerateSeed()` in as
`CUSTOM_RAND_GENERATE_SEED`, seeding wolfCrypt's Hash-DRBG rather than
replacing it, so the DRBG, the repeated block check on the raw seed, and
periodic reseeding all stay in place. `whal_Rng_Generate()` is called once per
seed and reseed instead of for every byte of key material.

To use the wolfHAL RNG output directly, without the DRBG on top, define
`CUSTOM_RAND_GENERATE_BLOCK` in `user_settings.h`; the seed wiring backs off
when `CUSTOM_RAND_GENERATE_SEED` is already defined. This is correct only when
the wolfHAL backend is itself a conditioned DRBG rather than a raw TRNG.
