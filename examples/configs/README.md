# Example build configurations

Example wolfSSL configuration file templates for use when autoconf is not available, such as building with a custom IDE.

## Files

* `user_settings_template.h`: Template that allows modular algorithm and feature selection using `#if 0`/`#if 1` gates.
* `user_settings_all.h`: This is wolfSSL with all features enabled. Equivalent to `./configure --enable-all`.
* `user_settings_arduino.h`: An example Arduino file. See also [wolfSSL/Arduino-wolfSSL](https://github.com/wolfSSL/Arduino-wolfSSL).
* `user_settings_EBSnet.h`: Example configuration file for use with EBSnet ports.
* `user_settings_eccnonblock.h`: Example for non-blocking ECC crypto only. See comment at top for test results.
* `user_settings_espressif.h`: Example configuration for Espressif ESP32. See also [wolfSSL/IDE/Espressif](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif).
* `user_settings_fipsv2.h`: The FIPS v2 (3389) 140-2 certificate build options.
* `user_settings_fipsv5.h`: The FIPS v5 (ready) 140-3 build options. Equivalent to `./configure --enable-fips=v5-dev`.
* `user_settings_curve25519nonblock.h`: Example Curve25519 (X25519) non-blocking configuration.
* `user_settings_min_ecc.h`: Minimal ECC and SHA-256 only (no TLS). For ECC verify only add `NO_ECC_SIGN`.
* `user_settings_platformio.h`: An example for PlatformIO library. See also [platformio/wolfssl](https://registry.platformio.org/libraries/wolfssl/wolfssl).
* `user_settings_stm32.h`: Example configuration file generated from the wolfSSL STM32 Cube pack.
* `user_settings_tls12.h`: Example for TLS v1.2 client only, ECC only, AES-GCM only, SHA2-256 only.
* `user_settings_tls13.h`: TLS 1.3 only configuration (no TLS 1.2). Modern cipher suites with X25519/X448 key exchange.
* `user_settings_dtls13.h`: DTLS 1.3 for IoT and embedded. Includes connection ID support and smaller MTU options.
* `user_settings_pq.h`: Post-quantum TLS with ML-KEM (Kyber) key exchange and ML-DSA (Dilithium) certificates.
* `user_settings_openssl_compat.h`: OpenSSL compatibility layer for drop-in replacement. Enables OPENSSL_ALL and related APIs.
* `user_settings_baremetal.h`: Bare metal configuration. No filesystem, static memory only, minimal footprint.
* `user_settings_rsa_only.h`: RSA-only configuration (no ECC). For legacy systems requiring RSA cipher suites.
* `user_settings_pkcs7.h`: PKCS#7/CMS configuration for signing and encryption. S/MIME, firmware signing. For RSA-PSS SignedData (CMS RSASSA-PSS), define `WC_RSA_PSS`; see doxygen \ref PKCS7_RSA_PSS.
* `user_settings_ca.h`: Certificate Authority / PKI operations. Certificate generation, signing, CRL, OCSP.
* `user_settings_wolfboot_keytools.h`: wolfBoot key generation and signing tool. Supports ECC, RSA, ED25519, ED448, and post-quantum (ML-DSA/Dilithium, LMS, XMSS).
* `user_settings_wolfssh.h`: Minimum options for building wolfSSH. See comment at top for ./configure used to generate.
* `user_settings_wolftpm.h`: Minimum options for building wolfTPM. See comment at top for ./configure used to generate.

## Usage

1. Copy to your local project and rename to `user_settings.h`.
2. Add pre-processor macro `WOLFSSL_USER_SETTINGS` to your project.
3. Make sure and include `#include <wolfssl/wolfcrypt/settings.h>` prior to any other wolfSSL headers in your application.

## Testing with Autoconf

To use these with autoconf:

1. Copy file to root as `user_settings.h`.
2. Run `./configure --enable-usersettings --disable-examples && make`
