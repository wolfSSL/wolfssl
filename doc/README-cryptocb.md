# wolfSSL / wolfCrypt Crypto Callback (CryptoCb) Feature

This document describes the Crypto Callback feature and which compile-time options affect the ABI and structure of the `wc_CryptoInfo` structure used in callbacks.

## Quick Reference: ABI-Affecting Options

The following compile-time options modify the `wc_CryptoInfo` structure layout and therefore affect ABI compatibility:

| Category | Options |
|----------|---------|
| **Master Enable** | `WOLF_CRYPTO_CB`, `WOLF_CRYPTO_DEV` (alias) |
| **RSA** | `NO_RSA`, `WOLF_CRYPTO_CB_RSA_PAD`, `WOLFSSL_KEY_GEN` |
| **ECC** | `HAVE_ECC`, `HAVE_ECC_DHE`, `HAVE_ECC_SIGN`, `HAVE_ECC_VERIFY`, `HAVE_ECC_CHECK_KEY` |
| **Curve25519/Ed25519** | `HAVE_CURVE25519`, `HAVE_ED25519` |
| **Post-Quantum** | `WOLFSSL_HAVE_MLKEM`, `HAVE_FALCON`, `HAVE_DILITHIUM` |
| **AES** | `NO_AES`, `HAVE_AESGCM`, `HAVE_AESCCM`, `HAVE_AES_CBC`, `WOLFSSL_AES_COUNTER`, `HAVE_AES_ECB` |
| **DES3** | `NO_DES3` |
| **Hash** | `NO_SHA`, `NO_SHA256`, `WOLFSSL_SHA224`, `WOLFSSL_SHA384`, `WOLFSSL_SHA512`, `WOLFSSL_SHA3` |
| **HMAC/CMAC** | `NO_HMAC`, `WOLFSSL_CMAC` |
| **RNG** | `WC_NO_RNG` |
| **Certificates** | `NO_CERTS` |
| **Extended Callbacks** | `WOLF_CRYPTO_CB_CMD`, `WOLF_CRYPTO_CB_COPY`, `WOLF_CRYPTO_CB_FREE` |
| **KDF** | `HAVE_HKDF`, `HAVE_CMAC_KDF` |
| **Structure Layout** | `HAVE_ANONYMOUS_INLINE_AGGREGATES` |

## Overview

The Crypto Callback feature allows users to register custom callback functions that can intercept and handle cryptographic operations. This enables:

- Hardware acceleration integration
- Custom key storage implementations
- Cryptographic operation logging/auditing
- Integration with external crypto modules (HSMs, TPMs, etc.)

The feature is enabled using:
```
./configure --enable-cryptocb
```
or by defining `WOLF_CRYPTO_CB` in your build configuration.

## Interface Version

The crypto callback interface version is tracked by the `CRYPTO_CB_VER` macro defined in `wolfssl/wolfcrypt/cryptocb.h`:

```c
#define CRYPTO_CB_VER   2
```

This version number should be incremented when changes are made to the Crypto Callback interface.

## The wc_CryptoInfo Structure

The `wc_CryptoInfo` structure is defined in `wolfssl/wolfcrypt/cryptocb.h` and is the primary structure passed to crypto callback functions. It contains all the information needed to perform cryptographic operations.

The structure uses **conditional compilation** extensively, meaning the actual size and layout of the structure depends on which compile-time options are enabled. This is important for ABI compatibility: **code compiled with different options may have incompatible `wc_CryptoInfo` structures**.

## Compile-Time Options That Affect the ABI

The following compile-time options add or remove fields from the `wc_CryptoInfo` structure, thereby affecting its ABI:

### Master Enable Flag

| Option | Description |
|--------|-------------|
| `WOLF_CRYPTO_CB` | Master enable for the entire crypto callback feature. When disabled, the entire `wc_CryptoInfo` structure and callback system is unavailable. Note: `WOLF_CRYPTO_DEV` is an alias that automatically enables `WOLF_CRYPTO_CB`. |

### RSA Options

| Option | Effect on Structure |
|--------|-------------------|
| `NO_RSA` | When defined, **removes** the `rsa`, `rsa_check`, and `rsa_get_size` structs from the `pk` union |
| `WOLF_CRYPTO_CB_RSA_PAD` | When defined, **adds** `RsaPadding *padding` field to the `rsa` struct. This is auto-enabled when `WOLF_CRYPTO_CB` is defined with `WOLFSSL_RENESAS_TSIP`. |
| `WOLFSSL_KEY_GEN` | When defined, **adds** the `rsakg` struct for RSA key generation |

### ECC Options

| Option | Effect on Structure |
|--------|-------------------|
| `HAVE_ECC` | When defined, **adds** ECC-related structs to the `pk` union |
| `HAVE_ECC_DHE` | When defined with `HAVE_ECC`, **adds** `eckg` and `ecdh` structs |
| `HAVE_ECC_SIGN` | When defined with `HAVE_ECC`, **adds** `eccsign` struct |
| `HAVE_ECC_VERIFY` | When defined with `HAVE_ECC`, **adds** `eccverify` struct |
| `HAVE_ECC_CHECK_KEY` | When defined with `HAVE_ECC`, **adds** `ecc_check` struct |

### Curve25519/Ed25519 Options

| Option | Effect on Structure |
|--------|-------------------|
| `HAVE_CURVE25519` | When defined, **adds** `curve25519kg` and `curve25519` structs for Curve25519 key exchange |
| `HAVE_ED25519` | When defined, **adds** `ed25519kg`, `ed25519sign`, and `ed25519verify` structs for Ed25519 signatures |

### Post-Quantum Cryptography Options

| Option | Effect on Structure |
|--------|-------------------|
| `WOLFSSL_HAVE_MLKEM` | When defined, **adds** `pqc_kem_kg`, `pqc_encaps`, and `pqc_decaps` structs for ML-KEM (the NIST standardized Key Encapsulation Mechanism) operations |
| `HAVE_FALCON` | When defined (with or without `HAVE_DILITHIUM`), **adds** PQC signature structs |
| `HAVE_DILITHIUM` | When defined (with or without `HAVE_FALCON`), **adds** `pqc_sig_kg`, `pqc_sign`, `pqc_verify`, and `pqc_sig_check` structs |

### AES Options

| Option | Effect on Structure |
|--------|-------------------|
| `NO_AES` | When defined (along with `NO_DES3`), **removes** the entire `cipher` struct from the union |
| `HAVE_AESGCM` | When defined, **adds** `aesgcm_enc` and `aesgcm_dec` fields to the `cipher` union |
| `HAVE_AESCCM` | When defined, **adds** `aesccm_enc` and `aesccm_dec` fields to the `cipher` union |
| `HAVE_AES_CBC` | When defined, **adds** `aescbc` struct to the `cipher` union |
| `WOLFSSL_AES_COUNTER` | When defined, **adds** `aesctr` struct to the `cipher` union |
| `HAVE_AES_ECB` | When defined, **adds** `aesecb` struct to the `cipher` union |

### DES3 Options

| Option | Effect on Structure |
|--------|-------------------|
| `NO_DES3` | When defined (along with `NO_AES`), **removes** the entire `cipher` struct. When only `NO_DES3` is defined, **removes** the `des3` struct from the `cipher` union |

### Hash Options

| Option | Effect on Structure |
|--------|-------------------|
| `NO_SHA` | When defined, **removes** the `wc_Sha* sha1` pointer from the `hash` union. If all hash algorithms are disabled (`NO_SHA`, `NO_SHA256`, and no `WOLFSSL_SHA*` options), the entire `hash` struct is removed. |
| `NO_SHA256` | When defined, **removes** the `wc_Sha256* sha256` pointer from the `hash` union. If all hash algorithms are disabled, the entire `hash` struct is removed. |
| `WOLFSSL_SHA224` | When defined, **adds** `wc_Sha224* sha224` pointer to the `hash` union |
| `WOLFSSL_SHA384` | When defined, **adds** `wc_Sha384* sha384` pointer to the `hash` union |
| `WOLFSSL_SHA512` | When defined, **adds** `wc_Sha512* sha512` pointer to the `hash` union |
| `WOLFSSL_SHA3` | When defined, **adds** `wc_Sha3* sha3` pointer to the `hash` union |

### HMAC Options

| Option | Effect on Structure |
|--------|-------------------|
| `NO_HMAC` | When defined, **removes** the `hmac` struct from the union |

### CMAC Options

| Option | Effect on Structure |
|--------|-------------------|
| `WOLFSSL_CMAC` | When defined, **adds** the `cmac` struct to the union |

### RNG Options

| Option | Effect on Structure |
|--------|-------------------|
| `WC_NO_RNG` | When defined, **removes** the `rng` and `seed` structs from the union |

### Certificate Options

| Option | Effect on Structure |
|--------|-------------------|
| `NO_CERTS` | When defined, **removes** the `cert` struct from the union |

### Extended Callback Options

| Option | Effect on Structure |
|--------|-------------------|
| `WOLF_CRYPTO_CB_CMD` | When defined, **adds** the `cmd` struct for command operations (register/unregister callbacks) |
| `WOLF_CRYPTO_CB_COPY` | When defined, **adds** the `copy` struct for copy operations (copying crypto contexts) |
| `WOLF_CRYPTO_CB_FREE` | When defined, **adds** the `free` struct for free operations (freeing crypto contexts) |

### KDF Options

| Option | Effect on Structure |
|--------|-------------------|
| `HAVE_HKDF` | When defined, **adds** the `kdf` struct with `hkdf` sub-struct |
| `HAVE_CMAC_KDF` | When defined, **adds** `twostep_cmac` sub-struct to the `kdf` union |

### Structure Layout Options

| Option | Effect on Structure |
|--------|-------------------|
| `HAVE_ANONYMOUS_INLINE_AGGREGATES` | When defined, enables anonymous unions within the structure, which affects the memory layout and how fields are accessed |

## API Functions

The main API functions for using the crypto callback feature are:

```c
/* Register a crypto callback */
int wc_CryptoCb_RegisterDevice(int devId, CryptoDevCallbackFunc cb, void* ctx);

/* Unregister a crypto callback */
void wc_CryptoCb_UnRegisterDevice(int devId);

/* Get the default device ID */
int wc_CryptoCb_DefaultDevID(void);
```

### Optional API Functions

When `WOLF_CRYPTO_CB_FIND` is defined, an additional API is available:

```c
/* Set a callback to find which device should handle an algorithm */
typedef int (*CryptoDevCallbackFind)(int devId, int algoType);
void wc_CryptoCb_SetDeviceFindCb(CryptoDevCallbackFind cb);
```

When `DEBUG_CRYPTOCB` is defined, a debug helper is available:

```c
/* Print information about a wc_CryptoInfo structure */
void wc_CryptoCb_InfoString(wc_CryptoInfo* info);
```

The callback function signature is:

```c
typedef int (*CryptoDevCallbackFunc)(int devId, struct wc_CryptoInfo* info, void* ctx);
```

## ABI Compatibility Considerations

When using the crypto callback feature, ensure that:

1. **All code using `wc_CryptoInfo` is compiled with the same set of options** - The structure size and layout varies based on compile-time options.

2. **Check `CRYPTO_CB_VER`** - If you're developing a plugin or library that uses crypto callbacks, check the version number to ensure compatibility.

3. **Document your build options** - When distributing libraries that use crypto callbacks, document which options were enabled during compilation.

4. **Consider `HAVE_ANONYMOUS_INLINE_AGGREGATES`** - This option enables anonymous unions/structs (C11 feature), which affects how fields are accessed:
   - **With** this option: Access fields directly, e.g., `info->rsa.key`
   - **Without** this option: Access through named unions, e.g., `info->pk.rsa.key`
   - **Portability**: Some older compilers may not support anonymous aggregates. If targeting older platforms, avoid this option.

## Example Usage

```c
#include <wolfssl/wolfcrypt/cryptocb.h>

/* Custom callback function */
int myCryptoCallback(int devId, wc_CryptoInfo* info, void* ctx)
{
    /* Check the algorithm type */
    switch (info->algo_type) {
        case WC_ALGO_TYPE_PK:
            /* Handle public key operations */
            switch (info->pk.type) {
#ifndef NO_RSA
                case WC_PK_TYPE_RSA:
                    /* Handle RSA */
                    break;
#endif
#ifdef HAVE_ECC
                case WC_PK_TYPE_ECDSA_SIGN:
                    /* Handle ECC signing */
                    break;
#endif
            }
            break;
        case WC_ALGO_TYPE_CIPHER:
            /* Handle cipher operations */
            break;
        case WC_ALGO_TYPE_HASH:
            /* Handle hash operations */
            break;
    }
    
    /* Return CRYPTOCB_UNAVAILABLE to fall back to software */
    return CRYPTOCB_UNAVAILABLE;
}

int main(void)
{
    int devId = 1;
    
    /* Register the callback */
    wc_CryptoCb_RegisterDevice(devId, myCryptoCallback, NULL);
    
    /* Use wolfSSL with the devId */
    /* ... */
    
    /* Cleanup */
    wc_CryptoCb_UnRegisterDevice(devId);
    
    return 0;
}
```

## Related Documentation

- [README-async.md](README-async.md) - Documentation for asynchronous cryptography support
- [wolfSSL Manual](https://www.wolfssl.com/documentation/wolfSSL-Manual.pdf) - Complete wolfSSL documentation
- [wolfCrypt API](https://www.wolfssl.com/doxygen/wolfcrypt_API.html) - wolfCrypt API reference

## Support

For questions, please contact wolfSSL support at support@wolfssl.com
