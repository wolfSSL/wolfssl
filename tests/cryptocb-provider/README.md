# CryptoCB Provider

This directory contains an external cryptocb provider library for testing wolfSSL
builds with `WOLF_CRYPTO_CB_ONLY_*`  flags enabled.

## Background

When wolfSSL is built with CRYPTOCB_ONLY flags, the software crypto
implementations are removed from the library. This breaks the test suite since
tests cannot execute crypto operations without a real hardware provider or
software fallback.

This external provider solves the problem by:
1. Building a separate shared library with full software crypto implementations
2. Exporting a crypto callback that the test harness can dlopen() at runtime
3. Allowing tests to run even when the main wolfSSL has software crypto removed

## Problem

The external cryptocb and the main library must share a configuration so that
the ABI of the crypto callback doesn't change.

The external proider solves this problem by using a custom user_settings.h file
that is obtained by:

- including either options.h or user_settings.h from the main library.
- removing the following features:
  - TLS library stack (and so defining wolfcrypt_only)
  - removing all `WOLF_CRYPTO_CB_ONLY_*` features

## Building

To keep things simple the external provider use a simple Makefile with *
inclusion of all source files of the main library.
The source files are built in a single gcc invocation, no .o are shared between
the main library and the external provider.

### Via Autotools (Recommended)

The provider is automatically built when configuring with `--enable-cryptocb`:

```bash
./autogen.sh
./configure --enable-cryptocb
make
```

The library will be built at `tests/external-crypto-provider/libextcryptoprovider.so`.

The autotools just run the simple `Makefile` inside the folder, the external
provider itself just uses a very simple `Makefile`

### Standalone Build

You can also build the provider manually:

```bash
cd tests/external-crypto-provider
make WOLFSSL_DIR=/path/to/wolfssl
```

## Usage

### Automatic (Test Harness)

When running wolfcrypt tests with CRYPTOCB_ONLY builds and with
`WOLF_CRYPTO_CB_USE_EXT_PROVIDER` the test harness
automatically loads the provider:

The provider is loaded from
`tests/external-crypto-provider/libextcryptoprovider.so`.

The provided registered with  valid devid that is also used by `WC_USE_DEVID`

This way all tests are routed to the callback provider.

When the external provider is activated, all test suite is executed, even for
CRYPTOCB_ONLY builds.


### Provider loading

To use the provider:

```c
#include <dlfcn.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

/* Function pointer types */
typedef int (*callback_fn)(int, struct wc_CryptoInfo*, void*);

void* handle = dlopen("libextcryptoprovider.so", RTLD_NOW | RTLD_LOCAL);

callback_fn callback = dlsym(handle, "external_provider_callback");

/* Initialize and register */
init();
wc_CryptoCb_RegisterDevice(MY_DEV_ID, callback, NULL);

/* ... use wolfSSL with keys initialized with devId = MY_DEV_ID ... */

/* Cleanup */
wc_CryptoCb_UnRegisterDevice(MY_DEV_ID);
cleanup();
dlclose(handle);
```

## Supported Operations

The provider currently only supports operation with CB_ONLY supports:

- **RSA**: Raw RSA operations only (modular exponentiation).
- **ECC**: Key generation, ECDSA sign/verify, ECDH key agreement
