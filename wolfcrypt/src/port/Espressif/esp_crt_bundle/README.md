# wolfSSL Support for ESP-IDF Certificate Bundles

These files are typically only used when integrating wolfSSL with the ESP-IDF
and with the intention of using Certificate Bundles in the esp-tls component.

See the ESP-IDF `idf.py menuconfig`. A recent version of the [wolfSSL Kconfig](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/examples/template/components/wolfssl/Kconfig)
file is needed. The [template example](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/template)
can be use for creating a project-specific [wolfSSL component](https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples/template/components/wolfssl)
when not using a [Managed Component](https://www.wolfssl.com/wolfssl-now-available-in-espressif-component-registry/).

## Getting Started

Use the `idf.py menuconfig`,

When in doubt, delete the `./build` directory. This is particularly important when changing Certificate Bundle PEM files.

## Certificate Inspection

The certificates in the bundle are in PEM format. The [gen_crt_bundle.py script](./gen_crt_bundle.py)
converts them to DER format to load into the `x509_crt_imported_bundle_wolfssl_bin_start` binary
array.

To convert a PEM to DER from command-line:

```
MY_CERT_NAME=ISRG_ROOT_X1
openssl x509 -outform der -in "$MY_CERT_NAME".pem -out "$MY_CERT_NAME".der
```

To inspect a DER file:

```
openssl x509 -inform der -in "$MY_CERT_NAME".der -text -noout
```


## Known Problems and Issues

Here are the areas that may need attention. Most are related to older published versions of the ESP-IDF
that may not yet have wolfSSL integration. An updated ESP-IDF is required to use wolfSSL component _in_ the ESP-IDF.
There's a [gojimmypi V5.2.2 WIP Branch](https://github.com/gojimmypi/esp-idf/tree/my_522/components/lwip) for reference
until a PR is created for upstream support.

### Time

The wolfSSL libraries are by default considerably more robust and strict. As such, it is important to have an accurate
time and date setting for the certificate date ranges.. The wolfssL libraries include some
[time helper functions](https://github.com/wolfSSL/wolfssl/blob/master/wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h).
These can be enabled with `#define USE_WOLFSSL_ESP_SDK_TIME` in the `user_settings.h`.

Alternatively, the `WOLFSSL_DEBUG_IGNORE_ASN_TIME` can be used to ignore the time. This is strongly discouraged in anything
other than a development / test environment where the time is known to be incorrect.

### Examples may need to have wolfSSL Certificate Bundles enabled.

In cases where [some examples are gated out](https://github.com/espressif/esp-idf/blob/c9df77efbf871d4c3ae9fb828778ff8c4ab36804/examples/protocols/esp_http_client/main/esp_http_client_example.c#L419),
the "or" needs to be added for `CONFIG_WOLFSSL_CERTIFICATE_BUNDLE` option like this:

```
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE || CONFIG_WOLFSSL_CERTIFICATE_BUNDLE
```

### Adding Embedded Certificates

The `main` app directory has a [CMakeLists.txt](https://github.com/espressif/esp-idf/blob/6e5414b6c4f265a0adfb56a15fbfbe6beb1f8373/examples/protocols/esp_http_client/main/CMakeLists.txt#L10)
with the `idf_component_register` function:

```
idf_component_register(SRCS "esp_http_client_example.c"
                      INCLUDE_DIRS "."
                      REQUIRES ${requires}
                      EMBED_TXTFILES howsmyssl_com_root_cert.pem
                                     postman_root_cert.pem)
```

This data ends up in the [extern const char](https://github.com/espressif/esp-idf/blob/6e5414b6c4f265a0adfb56a15fbfbe6beb1f8373/examples/protocols/esp_http_client/main/esp_http_client_example.c#L45)
arrays:

```
extern const char howsmyssl_com_root_cert_pem_start[] asm("_binary_howsmyssl_com_root_cert_pem_start");
extern const char howsmyssl_com_root_cert_pem_end[]   asm("_binary_howsmyssl_com_root_cert_pem_end");

extern const char postman_root_cert_pem_start[] asm("_binary_postman_root_cert_pem_start");
extern const char postman_root_cert_pem_end[]   asm("_binary_postman_root_cert_pem_end");
```

When changing the source files (also located in the `main` directory) - it is usually best to
delete the `./build` directory to ensure fresh contents get parsed in as desired.

VS Code / PlatformIO users can consider deleting the `./pio` and `./vscode` directories.

Visual Studio/VisualGDB users can remove the `./vs` and `.visualgdb`.

### TLS 1.3 issues with howsmyssl.com

Espressif is using the well known https://www.howsmyssl.com/ in the
[examples](https://github.com/espressif/esp-idf/tree/master/examples/protocols/), for instance in
the [esp_http_client](https://github.com/espressif/esp-idf/tree/master/examples/protocols/esp_http_client).

It was recently observed that TLS 1.3 is _not_ currently configured properly on that web site.
See [howsmyssl #716](https://github.com/jmhodges/howsmyssl/issues/716).

As such, when configuring wolfSSL for _only_ TLS 1.3, a `fatal error -313` may occur.

Additionally, not that there's a [cert in the app](https://github.com/espressif/esp-idf/blob/c9df77efbf871d4c3ae9fb828778ff8c4ab36804/examples/protocols/esp_http_client/main/esp_http_client_example.c#L45)
in `howsmyssl_com_root_cert_pem_start`, separate from the bundle certificate data. Take note of this when
attempting to simply change `www.howsmyssl.com` to `www.google.com`.


### postman

Beware there's a hard-coded PEM certificate for the [postman root cert](https://github.com/espressif/esp-idf/blob/c9df77efbf871d4c3ae9fb828778ff8c4ab36804/examples/protocols/esp_http_client/main/esp_http_client_example.c#L48)
(not in the bundle). If you see a failure, the data may need to be updated.

See the comments for adding certificate data, copied here for reference:

>Root cert for howsmyssl.com, taken from howsmyssl_com_root_cert.pem

>The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null

>The CA root cert is the last cert given in the chain of certs.

>To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.

## Timeout

Occasionally there may be connection timeouts. This is not specific to wolfSSL. The root cause is likely CDN related.

See the `.timeout_ms` and make adjustments as necessary in the `esp_http_client_config_t`:.

```
    esp_http_client_config_t config = {
        .url = "https://postman-echo.com/post",
        .event_handler = _http_event_handler,
        .cert_pem = postman_root_cert_pem_start,
        .is_async = true,
        .timeout_ms = 5000,
    };
```

## Failed to load CA

This is expected to be a common error to encounter:

```
E (28454) esp_crt_bundle-wolfssl: Failed to load CA
W (28454) esp_crt_bundle-wolfssl: Warning: found a matching cert, but not added to the Certificate Manager. error: 0
E (28454) esp_crt_bundle-wolfssl: Did not find a matching crt
E (28464) internal.c: ssl != NULL; no callback, verifyFail = 1
W (28474) internal.c: CleanupStoreCtxCallback
E (28474) internal.c: DoCertFatalAlert = -188
E (28484) esp-tls-wolfssl: wolfSSL_connect returned -1, error code: -188
E (28484) esp-tls-wolfssl: Failed to verify peer certificate , returned 24
E (28494) esp-tls: Failed to open new connection
E (28504) transport_base: Failed to open a new connection
E (28514) HTTP_CLIENT: Connection failed, sock < 0
E (28514) HTTP_CLIENT: HTTP request failed: ESP_ERR_HTTP_CONNECT
```

The problem here is that the example [esp_http_client](https://github.com/espressif/esp-idf/tree/master/examples/protocols/esp_http_client)
app _does not work_ immediately out of the box unless changes are made to the source:

```
#ifdef CONFIG_ESP_TLS_USING_WOLFSSL
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>

    /* TODO: conditional bundle */
    #include <wolfssl/wolfcrypt/port/Espressif/esp_crt_bundle.h>
#endif
```

` openssl s_client -connect postman-echo.com:443 -CAfile ./postman.pem`

### Component esp-wolfssl needs to be installed

The wrong ESP-IDF toolchain is being used. Use the [gojimmypi my_522 branch](https://github.com/gojimmypi/esp-idf/tree/my_522).

```
-- Component esp-wolfssl needs to be installed. See api-reference/protocols/esp_tls docs.
CMake Error at /mnt/c/SysGCC/esp32/esp-idf/v5.2/tools/cmake/component.cmake:382 (message):
  Component esp-wolfssl not found
Call Stack (most recent call first):
  /mnt/c/SysGCC/esp32/esp-idf/v5.2/components/esp-tls/CMakeLists.txt:26 (idf_component_get_property)


-- Configuring incomplete, errors occurred!
```

## x509_crt_bundle_wolfssl.S not found

It is important to note that PlatformIO components can NOT be used for esp-tls.

The wolfSSL library MUST be used from either the local project `components` or from the ESP-IDF.

```
*** [.pio\bld_8mb_dbg_wolfssl\.pio\bld_8mb_dbg_wolfssl\x509_crt_bundle_wolfssl.S.o]
Source `.pio\bld_8mb_dbg_wolfssl\x509_crt_bundle_wolfssl.S' not found,
needed by target `.pio\bld_8mb_dbg_wolfssl\.pio\bld_8mb_dbg_wolfssl\x509_crt_bundle_wolfssl.S.o'.
```


## Error couldn't get hostname for not.existent.url

This error is as desired, showing that a bad URL will fail.

```
E (50613) esp-tls: couldn't get hostname for :not.existent.url: getaddrinfo() returns 202, addrinfo=0x0
E (50613) esp-tls: Failed to open new connection
E (50613) transport_base: Failed to open a new connection
E (50623) HTTP_CLIENT: Connection failed, sock < 0
E (50623) HTTP_CLIENT: Error perform http request ESP_ERR_HTTP_CONNECT
```

## Tool doesn't match supported version from list

Edit the `C:\Users\%USER%\.platformio\packages\framework-espidf\tools\tools.json` and replace
`13.2.0_20230928` with the desired version, such as `esp-13.2.0_20240530`.

```
  Tool doesn't match supported version from list ['esp-13.2.0_20230928']:
  C:/Users/gojimmypi/.platformio/packages/toolchain-xtensa-esp-elf/bin/xtensa-esp32-elf-gcc.exe
```

## ESP_ERROR_CHECK failed: esp_err_t 0xffffffff (ESP_FAIL) at 0x400d3b60

This is a generic `ESP_ERROR_CHECK` result, in this case the default WiFi SSID and password could not connect:


```
I (25970) example_connect: Wi-Fi disconnected, trying to reconnect...
I (28380) example_connect: WiFi Connect failed 7 times, stop reconnect.
ESP_ERROR_CHECK failed: esp_err_t 0xffffffff (ESP_FAIL) at 0x400d3b60
file: "main/esp_http_client_example.c" line 936
func: app_main
expression: example_connect()

abort() was called at PC 0x400890e3 on core 0
```

## Manual Testing

To test if the `howsmyssl` web site has TLS 1.3 working, use the [wolfSSL client example](https://github.com/wolfSSL/wolfssl/tree/master/examples/client):

```bash
./examples/client/client -v 4 -h www.howsmyssl.com -p 443 -g -j
```

Or OpenSSL:

```bash
openssl s_client -connect www.howsmyssl.com:443 -tls1_3 -ciphersuites 'TLS_AES_256_GCM_SHA384'
```

Returns this unintuitive error:

```text
$ openssl s_client -connect www.howsmyssl.com:443 -tls1_3 -ciphersuites 'TLS_AES_256_GCM_SHA384'
CONNECTED(00000003)
4007DA6C617F0000:error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1584:SSL alert number 40
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 7 bytes and written 247 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
```



Or OpenSSL,

```bash
openssl s_client -tls1_3 -host www.howsmyssl.com -port 443
```
