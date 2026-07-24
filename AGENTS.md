# wolfSSL Integration Guide for Agents

wolfSSL is a lightweight ANSI C (C90) TLS/DTLS library (up to TLS 1.3 and DTLS 1.3)
built on the wolfCrypt cryptography engine. It targets everything from bare-metal
microcontrollers and RTOSes to desktop/server systems. Dual licensed: GPLv3
(GPLv2 may be elected only for specific exception projects) or a commercial
license from wolfSSL Inc. (see `LICENSING`).

This file is for agents helping users *integrate wolfSSL into their own projects*.
If `AGENTS.local.md` or `CLAUDE.local.md` exists in the repository root, read
it before starting work. Those files are gitignored, carry maintainer- and
machine-specific instructions, and take precedence over this file.

## Choose an integration path

| Situation | Path |
|---|---|
| Unix-like host or cross-compile with a toolchain | Autotools (canonical, most tested) |
| CMake-based project (find_package, add_subdirectory, FetchContent) | CMake |
| IDE, RTOS, or bare-metal build with no configure step | `user_settings.h` + `-DWOLFSSL_USER_SETTINGS` |
| Zephyr | `zephyr/` (module.yml, Kconfig) |
| ESP-IDF | `IDE/Espressif/ESP-IDF/` (also published as a managed component) |
| Arduino / PlatformIO | `IDE/ARDUINO/`, `IDE/PlatformIO/` |
| Visual Studio | `wolfssl64.sln`, `wolfssl-VS2022.vcxproj`, `IDE/WIN*/` |
| Linux/BSD kernel module | `linuxkm/`, `bsdkm/` |
| Python / Rust / C# / Ada bindings | `wrapper/` |
| Other IDEs/platforms (Keil, IAR, STM32Cube, Renesas, Xcode, QNX, ...) | `IDE/` (~60 subdirectories, each with a README) |

## The one rule that prevents most integration bugs

The application must be compiled with the **same feature defines** as the library.
Feature macros change struct layouts and API availability; a mismatch compiles fine
and corrupts memory at runtime.

- Autotools/CMake builds generate `wolfssl/options.h` recording every define.
  Include `<wolfssl/options.h>` before any other wolfSSL header, or build the app
  with `-DWOLFSSL_USE_OPTIONS_H` so headers pull it in automatically.
- `user_settings.h` builds: define `WOLFSSL_USER_SETTINGS` for **both** the library
  and the application, and keep one shared `user_settings.h` on the include path.
- Never commit a generated `wolfssl/options.h` (it is per-configure output).

## Autotools build (primary)

```sh
./autogen.sh          # git checkouts only; needs autoconf/automake/libtool.
                      # Release tarballs from wolfssl.com ship a prebuilt configure.
./configure [options]
make -j
make check            # optional but recommended
sudo make install     # installs lib, headers, wolfssl.pc, cmake package files
```

- `./configure --help` lists all options (~374 `--enable-*`, ~29 `--with-*`).
  `configure.ac` is the source of truth for what each option defines.
- Extra defines: `./configure CFLAGS="-DWOLFSSL_DTLS_NO_HVR_ON_RESUME"` or
  `EXTRA_CFLAGS`. (`C_EXTRA_FLAGS` is deprecated but still works.)
- Cross-compile with the usual `--host=<triple>` plus `CC=...`.
- Consumption after install: `pkg-config --cflags --libs wolfssl`, or CMake
  `find_package(wolfssl)` (autotools installs the CMake package files too;
  disable with `--disable-cmake-install`).

### Commonly used configure options

Defaults already on: TLS 1.2/1.3, ECC, RSA, AES(+GCM), SHA-2, ChaCha20-Poly1305,
Curve25519/Ed25519, hardening (`--enable-harden`: timing resistance + blinding),
SP math. Most work is *adding* protocols/features or *shrinking* the build.

| Group | Options |
|---|---|
| Bundles | `--enable-all`, `--enable-all-crypto`, `--enable-distro`, `--enable-cryptonly` (wolfCrypt only, no TLS) |
| Small builds | `--enable-leanpsk`, `--enable-leantls`, `--enable-lowresource`, `--enable-tinytls13`, `--enable-smallstack`, `--enable-staticmemory`, `--disable-errorstrings` |
| Protocols | `--enable-dtls`, `--enable-dtls13`, `--enable-quic`, `--enable-sctp`, `--enable-srtp`, `--enable-oldtls` (TLS 1.0/1.1), `--disable-tls13` |
| TLS features | `--enable-sni`, `--enable-alpn`, `--enable-session-ticket`, `--enable-earlydata`, `--enable-secure-renegotiation`, `--enable-maxfragment`, `--enable-ocsp`, `--enable-ocspstapling`, `--enable-crl`, `--enable-hrrcookie` |
| Extra crypto | `--enable-aesccm`, `--enable-aesctr`, `--enable-aesxts`, `--enable-curve448`, `--enable-ed448`, `--enable-sha3`, `--enable-rsapss`, `--enable-cmac`, `--enable-sm2 --enable-sm3 --enable-sm4-gcm` (ShangMi) |
| Post-quantum | `--enable-mlkem` (alias `--enable-kyber`), `--enable-mldsa` (alias `--enable-dilithium`), `--enable-falcon`, `--enable-lms`, `--enable-xmss` |
| Performance | `--enable-sp --enable-sp-asm` (default on x86_64/aarch64), `--enable-aesni`, `--enable-intelasm`, `--enable-armasm`, `--enable-riscv-asm`, `--enable-fastmath` |
| OpenSSL compat | `--enable-opensslextra` (common subset), `--enable-opensslall` (maximum), `--enable-opensslcoexist` (link both libraries) |
| App recipes | `--enable-curl`, `--enable-nginx`, `--enable-openssh`, `--enable-openvpn`, `--enable-haproxy`, `--enable-stunnel`, `--enable-wpas`, ... (each sets exactly the flags that project needs) |
| Platform | `--enable-singlethreaded`, `--disable-filesystem`, `--enable-usersettings` (read root `user_settings.h` instead of option defines) |
| Hardware/secure elements | `--enable-pkcs11`, `--enable-psa`, `--with-cryptoauthlib`, `--with-se050`, `--enable-caam`, `--enable-devcrypto`, `--enable-kcapi`, ... |
| Debug | `--enable-debug` (defines `DEBUG_WOLFSSL`, enables logging), `--enable-debug-trace-errcodes`, `--enable-valgrind` |
| FIPS | `--enable-fips=<ver>` (v2, v5, v6, ready, dev, ...). Certified versions need a licensed FIPS source bundle from wolfSSL Inc.; `ready`/`dev` build with the free FIPS Ready bundle from wolfssl.com. None configure from a plain git tree |

Option-to-macro mapping: nearly every `--enable-foo` maps 1:1 to a CMake
`-DWOLFSSL_FOO=yes` and to one or more C macros usable in `user_settings.h`.
To find the macro behind an option, grep `configure.ac` for the option name
and look at the `AM_CFLAGS="$AM_CFLAGS -D..."` lines, or grep `cmake/options.h.in`.

## CMake build

```sh
cmake -B build -DWOLFSSL_TLS13=yes -DWOLFSSL_DTLS=yes   # in-source builds are rejected
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build
```

- Minimum CMake 3.16. Option rule: `--enable-foo` == `-DWOLFSSL_FOO=yes`,
  `--disable-foo` == `-DWOLFSSL_FOO=no`. Plus standard `-DBUILD_SHARED_LIBS=ON/OFF`,
  `-DCMAKE_BUILD_TYPE=Debug|Release`, `-DWOLFSSL_EXAMPLES=no`, `-DWOLFSSL_CRYPT_TESTS=no`.
- CMake generates its own `<build>/wolfssl/options.h` (template: `cmake/options.h.in`).
- Consume installed package: `find_package(wolfssl CONFIG REQUIRED)` and link
  `wolfssl::wolfssl`. Working example: `cmake/consumer/`.
- Embedding the source tree with `add_subdirectory()`/`FetchContent` also works;
  link the `wolfssl` target.
- `-DWOLFSSL_USER_SETTINGS=yes` drops all option defines in favor of your
  `user_settings.h`.

## user_settings.h build (IDE / RTOS / bare-metal)

1. Pick a template from `examples/configs/` (26 of them, documented in its README):
   - `user_settings_template.h` -- modular starting point
   - `user_settings_all.h` (== `--enable-all`), `user_settings_tls12.h`,
     `user_settings_tls13.h`, `user_settings_tinytls13.h`, `user_settings_dtls13.h`
   - `user_settings_baremetal.h` (no filesystem, static memory),
     `user_settings_min_ecc.h`, `user_settings_rsa_only.h`
   - `user_settings_pq.h` (ML-KEM + ML-DSA), `user_settings_openssl_compat.h`
   - platform ones: `user_settings_stm32.h`, `user_settings_espressif.h`,
     `user_settings_arduino.h`, `user_settings_platformio.h`
   - `user_settings_fipsv2.h`, `user_settings_fipsv5.h`
2. Copy it into your project as `user_settings.h`, put its directory on the include
   path, and add `-DWOLFSSL_USER_SETTINGS` to all compilations (library and app).
3. Add sources to your build: `src/*.c` and `wolfcrypt/src/*.c`, **except** files
   that are `#include`d into others rather than compiled standalone:
   `src/ssl_*.c` (inlined into `src/ssl.c`), `wolfcrypt/src/evp.c` and
   `wolfcrypt/src/misc.c` (inlined unless `NO_INLINE` is defined). Add files from
   `wolfcrypt/src/port/<vendor>/` only for your hardware.
4. Include `<wolfssl/wolfcrypt/settings.h>` (or any wolfSSL header, which pulls it
   in) -- it reads `user_settings.h` first.

Sanity-check a config against this repo: copy it to the repo root as
`user_settings.h`, then `./configure --enable-usersettings --disable-examples && make`.

`wolfssl/wolfcrypt/settings.h` is the platform switchboard: it reacts to target
macros (`WOLFSSL_ESPIDF`, `FREERTOS`, `WOLFSSL_ZEPHYR`, `WOLFSSL_STM32F4`,
`MICROCHIP_PIC32`, `THREADX`, `MICRIUM`, `WOLFSSL_VXWORKS`, `EBSNET`, ...) and sets
up threading, memory, time, and filesystem primitives. Never edit `settings.h`;
set the macros in `user_settings.h` or your build flags.

## Where to look

| Path | Contents |
|---|---|
| `wolfssl/ssl.h` | Main TLS/DTLS API (`wolfSSL_*`) |
| `wolfssl/wolfcrypt/*.h` | Crypto APIs (`wc_*`): aes.h, ecc.h, rsa.h, sha256.h, random.h, ... |
| `wolfssl/openssl/*.h` | OpenSSL compatibility headers (with `--enable-opensslextra`) |
| `wolfssl/wolfio.h` | Transport I/O callback API |
| `wolfssl/wolfcrypt/settings.h` | Platform/feature switchboard (read-only) |
| `wolfssl/certs_test.h` | Test certs/keys as C arrays (for `NO_FILESYSTEM` demos only) |
| `wolfssl/internal.h` | Internal -- do not use from applications |
| `src/` | TLS implementation (ssl.c, tls13.c, dtls13.c, internal.c) |
| `wolfcrypt/src/` | Crypto implementations |
| `wolfcrypt/src/port/` | ~30 hardware/OS crypto ports: arm, intel, Espressif, Renesas, st, nxp, atmel, silabs, psa, kcapi, caam, liboqs, ... |
| `examples/client/`, `examples/server/` | Full-featured reference apps; run with `-h` for all flags |
| `examples/tls13/` | Minimal TLS 1.3 samples, incl. in-memory I/O (no sockets) |
| `examples/configs/` | The `user_settings_*.h` templates |
| `certs/` | Test certificates for examples/tests -- never use in production |
| `IDE/` | Per-IDE/platform project files and READMEs |
| `zephyr/`, `linuxkm/`, `bsdkm/`, `wrapper/` | Zephyr module, kernel modules, language bindings |
| `INSTALL` | Platform-by-platform build notes (iOS, Windows, Yocto, MQX, ...) |
| `doc/` | Pointers to the manual and Doxygen API docs |

## Minimal TLS client flow

```c
#include <wolfssl/options.h>   /* or user_settings.h scheme; must be first */
#include <wolfssl/ssl.h>

wolfSSL_Init();
WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
wolfSSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL);
WOLFSSL* ssl = wolfSSL_new(ctx);
wolfSSL_set_fd(ssl, sockfd);            /* connected TCP socket */
wolfSSL_connect(ssl);                   /* handshake (server: wolfSSL_accept) */
wolfSSL_write(ssl, msg, msgSz);
wolfSSL_read(ssl, buf, sizeof(buf));
wolfSSL_shutdown(ssl);
wolfSSL_free(ssl); wolfSSL_CTX_free(ctx); wolfSSL_Cleanup();
```

With `NO_FILESYSTEM`, use the buffer variants: `wolfSSL_CTX_load_verify_buffer()`,
`wolfSSL_CTX_use_certificate_buffer()`, `wolfSSL_CTX_use_PrivateKey_buffer()`.
On error, get details with `wolfSSL_get_error(ssl, ret)` and
`wolfSSL_ERR_error_string()`.

## Porting hooks

| Need | Hook | Where |
|---|---|---|
| Custom transport (no BSD sockets) | `wolfSSL_CTX_SetIORecv()` / `wolfSSL_CTX_SetIOSend()` + `wolfSSL_SetIOReadCtx()` / `wolfSSL_SetIOWriteCtx()` | `wolfssl/wolfio.h` |
| Custom allocator | `XMALLOC_USER` (your xmalloc/xfree/xrealloc), or `wolfSSL_SetAllocators()`, or `WOLFSSL_STATIC_MEMORY` (no heap) | `wolfssl/wolfcrypt/types.h`, `memory.h` |
| Entropy source | implement `wc_GenerateSeed()`, or define `CUSTOM_RAND_GENERATE_SEED` / `CUSTOM_RAND_GENERATE_BLOCK`, or `WC_RNG_SEED_CB` | `wolfssl/wolfcrypt/random.h`, `wolfcrypt/src/random.c` |
| Time source | `XTIME`/`XGMTIME` overrides, `NO_ASN_TIME` (`wc_port.h`); `USER_TICKS` low-res timer (`settings.h`) | `wolfssl/wolfcrypt/wc_port.h` |
| No RTOS / one thread | define `SINGLE_THREADED` (drops mutex deps) | `wolfssl/wolfcrypt/wc_port.h` |
| No filesystem | define `NO_FILESYSTEM`, use `*_buffer()` APIs | `wolfssl/wolfcrypt/wc_port.h` |
| Logging | build with `DEBUG_WOLFSSL` (`--enable-debug`), then `wolfSSL_Debugging_ON()`; redirect with `wolfSSL_SetLoggingCb()` (e.g. to a UART) | `wolfssl/wolfcrypt/logging.h` |
| Crypto offload / secure element | PKCS#11 (`--enable-pkcs11`), crypto callbacks (`wc_CryptoCb_RegisterDevice`, `WOLF_CRYPTO_CB`), or a `wolfcrypt/src/port/` driver | `wolfssl/wolfcrypt/cryptocb.h` |

## Verifying an integration

- `./wolfcrypt/test/testwolfcrypt` -- crypto self-test; `wolfcrypt/test/test.c` is
  portable and commonly compiled into embedded targets as a smoke test
  (call `wolfcrypt_test()`).
- `./wolfcrypt/benchmark/benchmark` -- crypto benchmark (also portable).
- `./examples/server/server` + `./examples/client/client` -- loopback TLS smoke
  test using `certs/`.
- Full suite in-repo: `make check` (autotools) or `ctest` (CMake).

## Gotchas

- Feature-define mismatch between lib and app is the #1 integration bug (see
  "The one rule" above). Symptoms: crashes or corruption inside otherwise-correct
  calls.
- `wolfSSL_Debugging_ON()` is a silent no-op unless the build defined
  `DEBUG_WOLFSSL`.
- Certificate loading fails (`ASN_NO_SIGNER_E`, error -188) when the CA is not
  loaded: wolfSSL verifies peers by default; load the CA chain or (dev only!)
  `wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL)`.
- `certs/` and `wolfssl/certs_test.h` are shared test credentials -- never ship
  them.
- Hardening (timing resistance/blinding) is on by default; `--disable-harden` is
  a security decision, not a build convenience.
- No `--enable-fips` variant builds from the plain git tree: configure errors out
  while `wolfcrypt/src/fips.c` is the empty stub. Certified FIPS (v2/v5/v6)
  requires a licensed source bundle from wolfSSL Inc.; `--enable-fips=ready` or
  `=dev` works with the free FIPS Ready download from wolfssl.com, running the
  full module machinery (integrity check, self-tests) but without a FIPS
  certificate.
- OpenSSL compat is source-level, not ABI-level: recompile the app against
  `wolfssl/openssl/*.h`; you cannot swap shared libraries under an
  OpenSSL-linked binary.

## Further documentation

- wolfSSL manual: https://www.wolfssl.com/documentation/manuals/wolfssl/
- API reference (wolfSSL + wolfCrypt Doxygen): `doc/dox_comments` directory
- Standalone example projects: https://github.com/wolfSSL/wolfssl-examples
- Support / commercial licensing: support@wolfssl.com
