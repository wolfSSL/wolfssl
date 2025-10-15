# PSoC6 Hardware Crypto Port for wolfSSL

This directory provides a hardware-accelerated cryptography port for Cypress PSoC6 devices, integrating the PSoC6 hardware crypto block with the wolfSSL cryptography library. The implementation leverages the PSoC6 hardware to accelerate various cryptographic hash and ECC operations, improving performance and reducing CPU load.

## Implemented Features

### 1. Hardware-Accelerated Hash Functions

The following hash algorithms are implemented using the PSoC6 hardware crypto block:

- **SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256**
  - All handled by the function `wc_Psoc6_Sha1_Sha2_Init`, which initializes the hardware for the selected hash mode.
  - The macros `PSOC6_HASH_SHA1` and `PSOC6_HASH_SHA2` (defined in `psoc6_crypto.h`) control which SHA-1 and SHA-2 family algorithms are available for hardware acceleration.
  - The corresponding wolfSSL macros (e.g., `WOLFSSL_SHA224`, `WOLFSSL_SHA384`, `WOLFSSL_SHA512`) must also be defined to enable the algorithm in the library.

- **SHA-3 Family**
  - Supported if `PSOC6_HASH_SHA3` (defined in `psoc6_crypto.h`) and `WOLFSSL_SHA3` are both defined.
  - Functions: `wc_Psoc6_Sha3_Init`, `wc_Psoc6_Sha3_Update`, `wc_Psoc6_Sha3_Final`
  - SHAKE support: `wc_Psoc6_Shake_SqueezeBlocks`
 - To enable SHAKE support (and use wc_Psoc6_Shake_SqueezeBlocks), you must define either `WOLFSSL_SHAKE128` or `WOLFSSL_SHAKE256` in addition to `WOLFSSL_SHA3` and hardware acceleration macros.

All hash operations are offloaded to the PSoC6 hardware, with mutex protection for thread safety.

### 2. Hardware-Accelerated ECDSA Verification

- **ECDSA Signature Verification**
  - Function: `psoc6_ecc_verify_hash_ex`
  - Uses PSoC6 hardware to verify ECDSA signatures for supported curves (up to secp521r1).
  - Enabled when `HAVE_ECC` is defined.

### 3. Crypto Block Initialization and Resource Management

- **Initialization**
  - Function: `psoc6_crypto_port_init`
  - Enables the PSoC6 crypto hardware block.
- **Resource Cleanup**
  - Function: `wc_Psoc6_Sha_Free`
  - Clears and synchronizes the hardware register buffer.

## Enable Hardware Acceleration

To enable PSoC6 hardware crypto acceleration for hash and ECC algorithms, ensure the following macros are defined:

- `WOLFSSL_PSOC6_CRYPTO` — Enables the PSoC6 hardware crypto port.
- The following are defined in `psoc6_crypto.h` and control which hardware hash accelerations are available:
  - `PSOC6_HASH_SHA1` — Enables SHA-1 hardware acceleration.
  - `PSOC6_HASH_SHA2` — Enables SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256) hardware acceleration.
  - `PSOC6_HASH_SHA3` — Enables SHA-3 family hardware acceleration.
- To enable the corresponding algorithms in wolfSSL, define the following macros as needed (typically in your `wolfssl/wolfcrypt/settings.h` or build system):
  - `WOLFSSL_SHA224` — Enable SHA-224 support.
  - `WOLFSSL_SHA384` — Enable SHA-384 support.
  - `WOLFSSL_SHA512` — Enable SHA-512, SHA-512/224, SHA-512/256 support.
  - `WOLFSSL_SHA3` — Enable SHA-3 support.
  - `WOLFSSL_SHAKE128`, `WOLFSSL_SHAKE256` — Enable SHAKE support.
  - `HAVE_ECC` — Enable ECC and ECDSA support.

**Example: Enabling SHA-1, SHA-2, and SHA-3 Hardware Acceleration**

In your build configuration or `wolfssl/wolfcrypt/settings.h`:
```c
#define WOLFSSL_PSOC6_CRYPTO
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_ECC
```
- No need to define `PSOC6_HASH_SHA1`, `PSOC6_HASH_SHA2`, or `PSOC6_HASH_SHA3` yourself; they are defined in `psoc6_crypto.h`.

## File Overview

- `psoc6_crypto.h`
  Header file declaring the hardware crypto interface and configuration macros.
- `psoc6_crypto.c`
  Implementation of the hardware-accelerated hash and ECC functions for PSoC6.

## Integration Notes

- The port expects the PSoC6 PDL (Peripheral Driver Library) to be available and included in your project.
- The hardware crypto block is initialized on first use; no manual initialization is required unless you wish to call `psoc6_crypto_port_init` directly.
- Hash operations are mutex-protected for thread safety.
- ECC hardware operations are not mutex-protected; if you use ECC functions from multiple threads, you must provide your own synchronization.
- The implementation is designed to be compatible with the wolfSSL API, so existing code using wolfSSL hash/ECC functions will automatically benefit from hardware acceleration when enabled.

---

For further details, refer to the comments in [`psoc6_crypto.h`](wolfssl/wolfssl-master/wolfcrypt/port/cypress/psoc6_crypto.h) and [`psoc6_crypto.c`](wolfssl/wolfssl-master/wolfcrypt/src/port/cypress/psoc6_crypto.c)
