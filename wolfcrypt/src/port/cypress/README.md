# PSoC6 Hardware Crypto Port for wolfSSL

This directory provides a hardware-accelerated cryptography port for Cypress PSoC6 devices, integrating the PSoC6 hardware crypto block with the wolfSSL cryptography library. The implementation leverages the PSoC6 hardware to accelerate various cryptographic operations including hash functions, AES encryption/decryption, and ECC verification, improving performance and reducing CPU load.

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

### 2. Hardware-Accelerated AES Functions

The following AES cipher modes are implemented using the PSoC6 hardware crypto block:

- **AES Block Operations**
  - Single-block encryption/decryption: `wc_Psoc6_Aes_Encrypt`, `wc_Psoc6_Aes_Decrypt`
  - Direct AES operations: `wc_Psoc6_Aes_EncryptDirect`, `wc_Psoc6_Aes_DecryptDirect` (enabled with `WOLFSSL_AES_DIRECT`)
  - Supports AES-128, AES-192, and AES-256 key sizes

- **AES-ECB (Electronic Codebook) Mode**
  - Multi-block encryption: `wc_Psoc6_Aes_EcbEncrypt`
  - Multi-block decryption: `wc_Psoc6_Aes_EcbDecrypt`
  - Enabled with `HAVE_AES_ECB`

- **AES-CBC (Cipher Block Chaining) Mode**
  - Multi-block encryption with IV chaining: `wc_Psoc6_Aes_CbcEncrypt`
  - Multi-block decryption with IV chaining: `wc_Psoc6_Aes_CbcDecrypt`
  - Automatically enabled with `HAVE_AES_CBC`

- **AES-CFB (Cipher Feedback) Mode**
  - Stream encryption: `wc_Psoc6_Aes_CfbEncrypt`
  - Stream decryption: `wc_Psoc6_Aes_CfbDecrypt`
  - Enabled with `WOLFSSL_AES_CFB`

- **AES-GCM (Galois/Counter Mode)**
  - Authenticated encryption: `wc_Psoc6_Aes_GcmEncrypt`
  - Authenticated decryption with tag verification: `wc_Psoc6_Aes_GcmDecrypt`
  - Provides both confidentiality and authenticity
  - Enabled with `HAVE_AESGCM`

All AES operations are offloaded to the PSoC6 hardware with mutex protection for thread safety.
### 3. Hardware-Accelerated ECDSA Verification

- **ECDSA Signature Verification**
  - Function: `psoc6_ecc_verify_hash_ex`
  - Uses PSoC6 hardware to verify ECDSA signatures for supported curves (up to secp521r1).
  - Enabled when `HAVE_ECC` is defined.

### 4. Crypto Block Initialization and Resource Management

- **Initialization**
  - Function: `psoc6_crypto_port_init`
  - Enables the PSoC6 crypto hardware block.
- **Resource Cleanup**
  - Hash functions: `wc_Psoc6_Sha_Free` — Clears and synchronizes the hardware register buffer
  - AES functions: `wc_Psoc6_Aes_Free` — Frees internal AES buffers and state

## Enable Hardware Acceleration

To enable PSoC6 hardware crypto acceleration, ensure the following macros are defined:

### Core Macro
- `WOLFSSL_PSOC6_CRYPTO` — Enables the PSoC6 hardware crypto port (required for all features)

### Hash Function Macros
- The following are defined in `psoc6_crypto.h` and control which hardware hash accelerations are available:
  - `PSOC6_HASH_SHA1` — Enables SHA-1 hardware acceleration
  - `PSOC6_HASH_SHA2` — Enables SHA-2 family hardware acceleration
  - `PSOC6_HASH_SHA3` — Enables SHA-3 family hardware acceleration
- To enable the corresponding algorithms in wolfSSL, define these macros (typically in your `wolfssl/wolfcrypt/settings.h` or build system):
  - `WOLFSSL_SHA224` — Enable SHA-224 support
  - `WOLFSSL_SHA384` — Enable SHA-384 support
  - `WOLFSSL_SHA512` — Enable SHA-512, SHA-512/224, SHA-512/256 support
  - `WOLFSSL_SHA3` — Enable SHA-3 support
  - `WOLFSSL_SHAKE128`, `WOLFSSL_SHAKE256` — Enable SHAKE support

### AES Function Macros
- AES hardware acceleration is automatically enabled when `NO_AES` is not defined
- To enable specific AES modes, define:
  - `HAVE_AES_ECB` — Enable AES-ECB mode
  - `HAVE_AES_CBC` — Enable AES-CBC mode (typically enabled by default)
  - `HAVE_AES_DECRYPT` — Enable AES decryption functions
  - `WOLFSSL_AES_DIRECT` — Enable direct AES block operations
  - `WOLFSSL_AES_CFB` — Enable AES-CFB mode
  - `HAVE_AESGCM` — Enable AES-GCM authenticated encryption

### ECC Function Macros
- `HAVE_ECC` — Enable ECC and ECDSA support

**Example: Enabling Full Hardware Acceleration**

In your build configuration or `wolfssl/wolfcrypt/settings.h`:
```c
#define WOLFSSL_PSOC6_CRYPTO

/* Hash functions */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* AES cipher modes */
#define HAVE_AES_ECB
#define HAVE_AES_CBC
#define HAVE_AES_DECRYPT
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_CFB
#define HAVE_AESGCM

/* ECC */
#define HAVE_ECC
```
- Note: `PSOC6_HASH_SHA1`, `PSOC6_HASH_SHA2`, and `PSOC6_HASH_SHA3` are automatically defined in `psoc6_crypto.h`; you don't need to define them explicitly.

## File Overview

- `psoc6_crypto.h`
  Header file declaring the hardware crypto interface and configuration macros.
- `psoc6_crypto.c`
  Implementation of the hardware-accelerated hash, AES, and ECC functions for PSoC6.

## Integration Notes

- The port expects the PSoC6 PDL (Peripheral Driver Library) to be available and included in your project.
- The hardware crypto block is initialized on first use; no manual initialization is required unless you wish to call `psoc6_crypto_port_init` directly.
- Hash and AES operations are mutex-protected for thread safety.
- ECC hardware operations are not mutex-protected; if you use ECC functions from multiple threads, you must provide your own synchronization.
- The implementation is designed to be compatible with the wolfSSL API, so existing code using wolfSSL hash/AES/ECC functions will automatically benefit from hardware acceleration when enabled.

---

For further details, refer to the comments in [`psoc6_crypto.h`](wolfssl/wolfssl-master/wolfcrypt/port/cypress/psoc6_crypto.h) and [`psoc6_crypto.c`](wolfssl/wolfssl-master/wolfcrypt/src/port/cypress/psoc6_crypto.c)
