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
points at the directory holding your `board.h`. The port forces a static-only
build: wolfHAL's objects are compiled by your application, so `libwolfssl.a`
is left with unresolved `whal_*` references for your final link to satisfy.
That also means wolfSSL's bundled examples and crypt tests are disabled.

## board.h

`board.h` is yours, not wolfSSL's, the same arrangement `settings.h` has with
`user_settings.h`. Both wolfHAL and wolfSSL find it by quoted include off your
`-I` path:

* wolfHAL's driver TUs (`src/crypto/stm32wb_aes.c`, `src/rng/stm32wb_rng.c`)
  expand the `WHAL_CFG_*_DEV` initializers in it to define their device
  singletons.
* wolfSSL's `wolfhal.c` reads it for the wolfHAL platform driver headers and
  for one device macro per algorithm:
  `WC_WOLFHAL_AES_{ECB,CBC,GCM,CCM}_DEV` and `WC_WOLFHAL_RNG_DEV`. The
  `BOARD_AES_*_DEV` / `BOARD_RNG_DEV` names a stock wolfHAL `board.h` already
  uses are accepted directly, so an in-tree wolfHAL board needs no additions.

Only the modes `board.h` names a device for are offloaded. A mode wolfSSL is
built with but `board.h` does not name is left to wolfCrypt's software
implementation, so hardware that covers, say, only GCM needs just
`WC_WOLFHAL_AES_GCM_DEV`, and a build with CBC enabled still links and runs.

`WC_WOLFHAL_RNG_DEV` is the exception. `wc_wolfHAL_GenerateBlock()` is wired in
as `CUSTOM_RAND_GENERATE_BLOCK`, which replaces the entropy source outright
rather than sitting behind a dispatch that can decline, so defining
`WOLFSSL_WOLFHAL_RNG` without a device is a build error.

Because the `BOARD_*_DEV` names are accepted, a stock `board.h` from wolfHAL's
`boards/` directory works as-is:

```sh
./configure --with-wolfhal=../wolfHAL \
            --with-wolfhal-board=../wolfHAL/boards/stm32wb55xx_nucleo
```

Use one of those as the starting point for a board wolfHAL does not already
cover.

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

Define `WOLFSSL_WOLFHAL_RNG` to build `wc_wolfHAL_GenerateBlock()`, and wire it
up in `user_settings.h` with:

```c
#define CUSTOM_RAND_GENERATE_BLOCK wc_wolfHAL_GenerateBlock
```
