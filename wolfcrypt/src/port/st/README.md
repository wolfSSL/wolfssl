# ST Ports

Support for the STM32 L4, F1, F2, F4, F7 and MP13 on-board crypto hardware
acceleration:
 - symmetric AES (ECB/CBC/CTR/GCM)
 - MD5/SHA1/SHA224/SHA256 (MP13 does not have MD5 acceleration)

Support for the STM32 PKA on WB55, H7, MP13 and other devices with on-board
public-key acceleration:
 - ECC192/ECC224/ECC256/ECC384

Support for the STSAFE-A secure element family via I2C for ECC supporting NIST P-256/P-384 and Brainpool 256/384-bit curves:
 - **STSAFE-A100/A110**: Uses ST's proprietary STSAFE-A1xx middleware. Contact us at support@wolfssl.com for integration assistance.
 - **STSAFE-A120**: Uses ST's open-source [STSELib](https://github.com/STMicroelectronics/STSELib) (BSD-3 license).


For details see our [wolfSSL ST](https://www.wolfssl.com/docs/stm32/) page.


## STM32 Symmetric Acceleration

We support using the STM32 CubeMX and Standard Peripheral Library.

### Building

To enable support define one of the following:

```
#define WOLFSSL_STM32L4
#define WOLFSSL_STM32F1
#define WOLFSSL_STM32F2
#define WOLFSSL_STM32F4
#define WOLFSSL_STM32F7
```

To use CubeMX define `WOLFSSL_STM32_CUBEMX` otherwise StdPeriLib is used.

To disable portions of the hardware acceleration you can optionally define:

```
#define NO_STM32_RNG
#define NO_STM32_CRYPTO
#define NO_STM32_HASH
```

### Coding

In your application you must include <wolfssl/wolfcrypt/settings.h> before any other wolfSSL headers. If building the sources directly we recommend defining `WOLFSSL_USER_SETTINGS` and adding your own `user_settings.h` file. You can find a good reference for this in `IDE/GCC-ARM/Header/user_settings.h`.


### Benchmarks

See our [benchmarks](https://www.wolfssl.com/docs/benchmarks/) on the wolfSSL website.


## STM32 PKA (Public Key Acceleration)

STM32 PKA is present in STM32WB55 as well as STM32H7 series.

### Building

To enable support define the following

`WOLFSSL_STM32_PKA`

### Using

When the support is enabled, the ECC operations will be accelerated using the PKA crypto co-processor.

## STSAFE-A ECC Acceleration

Using the wolfSSL PK callbacks or Crypto callbacks with the ST-Safe reference API's we support ECC operations for TLS client/server:
 - **ECDSA Sign/Verify**: P-256 and P-384 (NIST and Brainpool curves)
 - **ECDH Key Agreement**: For TLS key exchange
 - **ECC Key Generation**: Ephemeral keys for TLS

At the wolfCrypt level we also support ECC native API's for `wc_ecc_*` using the ST-Safe via Crypto Callbacks.

### Supported Hardware

| Model | Macro | SDK |
|-------|-------|-----|
| STSAFE-A100/A110 | `WOLFSSL_STSAFEA100` | ST STSAFE-A1xx Middleware (proprietary) |
| STSAFE-A120 | `WOLFSSL_STSAFEA120` | [STSELib](https://github.com/STMicroelectronics/STSELib) (BSD-3, open source) |

### Building

For STSAFE-A100/A110 (legacy):

```
./configure --enable-pkcallbacks CFLAGS="-DWOLFSSL_STSAFEA100"
```

or in `user_settings.h`:

```c
#define HAVE_PK_CALLBACKS
#define WOLFSSL_STSAFEA100
```

For STSAFE-A120 with STSELib:

```
./configure --enable-pkcallbacks CFLAGS="-DWOLFSSL_STSAFEA120"
```

or in `user_settings.h`:

```c
#define HAVE_PK_CALLBACKS
#define WOLFSSL_STSAFEA120
```

To use Crypto Callbacks (recommended for wolfCrypt-level ECC operations):

```c
#define WOLF_CRYPTO_CB
#define WOLFSSL_STSAFEA120  /* or WOLFSSL_STSAFEA100 */
```

### Coding

#### Using PK Callbacks (TLS)

Setup the PK callbacks for TLS using:

```c
/* Setup PK Callbacks for STSAFE */
WOLFSSL_CTX* ctx;
SSL_STSAFE_SetupPkCallbacks(ctx);

/* Or manually: */
wolfSSL_CTX_SetEccKeyGenCb(ctx, SSL_STSAFE_CreateKeyCb);
wolfSSL_CTX_SetEccSignCb(ctx, SSL_STSAFE_SignCertificateCb);
wolfSSL_CTX_SetEccVerifyCb(ctx, SSL_STSAFE_VerifyPeerCertCb);
wolfSSL_CTX_SetEccSharedSecretCb(ctx, SSL_STSAFE_SharedSecretCb);
wolfSSL_CTX_SetDevId(ctx, 0); /* enables wolfCrypt `wc_ecc_*` ST-Safe use */
```

The reference STSAFE PK callback functions are located in the `wolfcrypt/src/port/st/stsafe.c` file.

Adding a custom context to the callbacks:

```c
/* Setup PK Callbacks context */
WOLFSSL* ssl;
void* myOwnCtx;
SSL_STSAFE_SetupPkCallbackCtx(ssl, myOwnCtx);
```

#### Using Crypto Callbacks (wolfCrypt)

For direct wolfCrypt ECC operations using the hardware:

```c
#include <wolfssl/wolfcrypt/port/st/stsafe.h>

/* Register the crypto callback */
wolfSTSAFE_CryptoCb_Ctx stsafeCtx;
stsafeCtx.devId = WOLF_STSAFE_DEVID;
wc_CryptoCb_RegisterDevice(WOLF_STSAFE_DEVID, wolfSSL_STSAFE_CryptoDevCb, &stsafeCtx);

/* For ECDSA signing operations (uses persistent slot 1) */
ecc_key key;
wc_ecc_init_ex(&key, NULL, WOLF_STSAFE_DEVID);
wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
/* Sign operations will use STSAFE hardware */

/* For ECDH operations (uses ephemeral slot 0xFF) */
ecc_key ecdh_key;
wc_ecc_init_ex(&ecdh_key, NULL, WOLF_STSAFE_DEVID);
ecdh_key.devCtx = (void*)(uintptr_t)STSAFE_KEY_SLOT_EPHEMERAL;  /* Configure for ECDH */
wc_ecc_make_key_ex(&rng, 32, &ecdh_key, ECC_SECP256R1);
/* ECDH shared secret computation will use STSAFE hardware */
```

**Note for STSAFE-A120**: ECDH operations require keys generated in the ephemeral slot (0xFF) which has key establishment enabled by default. Set `key.devCtx = (void*)(uintptr_t)STSAFE_KEY_SLOT_EPHEMERAL;` to configure keys for ECDH before generation. Persistent slots (0-4) require explicit configuration via `put_attribute` command to enable key establishment.

### Implementation Details

The STSAFE support is self-contained in `wolfcrypt/src/port/st/stsafe.c` with SDK-specific implementations selected at compile time:

| Macro | SDK | Description |
|-------|-----|-------------|
| `WOLFSSL_STSAFEA100` | STSAFE-A1xx Middleware | ST's proprietary SDK for A100/A110 |
| `WOLFSSL_STSAFEA120` | [STSELib](https://github.com/STMicroelectronics/STSELib) | ST's open-source SDK for A120 (BSD-3) |

#### External Interface (Backwards Compatibility)

For customers with existing custom implementations, define `WOLFSSL_STSAFE_INTERFACE_EXTERNAL` to use an external `stsafe_interface.h` file instead of the built-in implementation:

```c
#define WOLFSSL_STSAFEA100  /* or WOLFSSL_STSAFEA120 */
#define WOLFSSL_STSAFE_INTERFACE_EXTERNAL
```

When `WOLFSSL_STSAFE_INTERFACE_EXTERNAL` is defined, the customer must provide a `stsafe_interface.h` header that defines:

| Item | Type | Description |
|------|------|-------------|
| `stsafe_curve_id_t` | typedef | Curve identifier type |
| `stsafe_slot_t` | typedef | Key slot identifier type |
| `STSAFE_ECC_CURVE_P256` | macro | P-256 curve ID value |
| `STSAFE_ECC_CURVE_P384` | macro | P-384 curve ID value |
| `STSAFE_KEY_SLOT_0/1/EPHEMERAL` | macros | Key slot values |
| `STSAFE_A_OK` | macro | Success return code |
| `STSAFE_MAX_KEY_LEN` | macro | Max key size in bytes (48) |
| `STSAFE_MAX_PUBKEY_RAW_LEN` | macro | Max public key size (96) |
| `STSAFE_MAX_SIG_LEN` | macro | Max signature size (96) |

And provide implementations for these internal interface functions:
- `int stsafe_interface_init(void)`
- `int stsafe_create_key(stsafe_slot_t*, stsafe_curve_id_t, uint8_t*)`
- `int stsafe_sign(stsafe_slot_t, stsafe_curve_id_t, uint8_t*, uint8_t*)`
- `int stsafe_verify(stsafe_curve_id_t, uint8_t*, uint8_t*, uint8_t*, uint8_t*, int32_t*)`
- `int stsafe_shared_secret(stsafe_slot_t, stsafe_curve_id_t, uint8_t*, uint8_t*, uint8_t*, int32_t*)`
- `int stsafe_read_certificate(uint8_t**, uint32_t*)`
- `int stsafe_get_random(uint8_t*, uint32_t)` (if `USE_STSAFE_RNG_SEED` defined)

When **NOT** defined (default behavior): All code is self-contained in `stsafe.c` using the appropriate SDK automatically.

The implementation provides these internal operations:

| Operation | Description |
|-----------|-------------|
| `stsafe_interface_init()` | Initialize the STSAFE device (called by `wolfCrypt_Init()`) |
| `stsafe_sign()` | ECDSA signature generation (P-256/P-384) |
| `stsafe_verify()` | ECDSA signature verification (P-256/P-384) |
| `stsafe_create_key()` | Generate ECC key pair on device |
| `stsafe_shared_secret()` | ECDH shared secret computation |
| `stsafe_read_certificate()` | Read device certificate from secure storage |

### STSELib Setup (A120)

For STSAFE-A120, you need to include the STSELib library:

1. Clone STSELib as a submodule or add to your project:
   ```bash
   git submodule add https://github.com/STMicroelectronics/STSELib.git lib/stselib
   ```

2. Add STSELib headers to your include path

3. Implement the platform abstraction files required by STSELib:
   - `stse_conf.h` - Configuration (target device, features)
   - `stse_platform_generic.h` - Platform callbacks (I2C, timing)

4. See STSELib documentation for platform-specific integration details

### Raspberry Pi with STSAFE-A120

For testing on a Raspberry Pi with an STSAFE-A120 connected via I2C:

1. **Enable I2C** on the Raspberry Pi:
   ```bash
   sudo raspi-config
   # Navigate to: Interface Options -> I2C -> Enable
   ```

2. **Verify the STSAFE device is detected** (default I2C address is 0x20):
   ```bash
   sudo i2cdetect -y 1
   ```

3. **Build wolfSSL with STSAFE-A120 support**:
   ```bash
   ./configure --enable-pkcallbacks --enable-cryptocb \
       CFLAGS="-DWOLFSSL_STSAFEA120 -I/path/to/STSELib"
   make
   sudo make install
   ```

4. **Platform abstraction**: Implement the STSELib I2C callbacks using the Linux I2C driver (`/dev/i2c-1`).

### Benchmarks and Memory Use

Software only implementation (STM32L4 120Mhz, Cortex-M4, Fast Math):

```
ECDHE    256 key gen       SW    4 ops took 1.278 sec, avg 319.500 ms,  3.130 ops/sec
ECDHE    256 agree         SW    4 ops took 1.306 sec, avg 326.500 ms,  3.063 ops/sec
ECDSA    256 sign          SW    4 ops took 1.298 sec, avg 324.500 ms,  3.082 ops/sec
ECDSA    256 verify        SW    2 ops took 1.283 sec, avg 641.500 ms,  1.559 ops/sec
```

Memory Use:

```
Peak Stack: 18456
Peak Heap: 2640
Total: 21096
```


STSAFE-A100 acceleration:

```
ECDHE    256 key gen       HW    8 ops took 1.008 sec, avg 126.000 ms,  7.937 ops/sec
ECDHE    256 agree         HW    6 ops took 1.051 sec, avg 175.167 ms,  5.709 ops/sec
ECDSA    256 sign          HW   14 ops took 1.161 sec, avg  82.929 ms, 12.059 ops/sec
ECDSA    256 verify        HW    8 ops took 1.184 sec, avg 148.000 ms,  6.757 ops/sec
```

Memory Use:

```
Peak Stack: 9592
Peak Heap: 170
Total: 9762
```


## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
