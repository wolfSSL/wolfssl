# QUIC in wolfSSL

This is an intermediate documentation about the added support for the QUIC protocol in wolfSSL. 
It is intended as a guide to reviewing the changes and a base for future update of the standard
wolfSSL documentation, once the changes have been reviewed.

## Configuration

QUIC support is enabled in the common autoconf style via:

```
> ./configure --enable-quic
```

this drags in some very basic features. To have everything necessary for a QUIC protocol implementation like ngtcpo2, one would do:

```
 ./configure --enable-quic --enable-session-ticket --enable-earlydata --enable-psk --enable-sni --enable-alpn
```

CMake support files have been updated as well, but not tested.

## Structure of Changes

The following files carry the main code added:

```
src/quic.c
wolfssl/quic.h
tests/quic.c
```

Additions to other files were necessary, protected by `#ifdef WOLFSSL_QUIC`, those cover:

* additions to `SSL_new()`, `SSL_free()`, `SSL_clear()`
* a new TLSX extension for QUIC transport parameters in QUICv1 and draft-27 versions. A new error code for when this is missing.
* a new `ssl->options` field to en-/disable TLSv1.3 MiddleBox Compat support, since this feature may not be active on a TLS13 session that is used by QUIC.
* handling of EarlyData without `EndOfEarlyData` messages being exchanged, since QUIC does not use those.

## API

The exposed API carries all methods that the [quictls/openssl](https://github.com/quictls/openssl) introduces. This seems to become the standard, since other *SLL libraries have picked those up or are about to. The methods are all in the `wolfSSL_` prefix. There are some additional methods, which are covered below.

### Core Interworking

At the base is the struct `WOLFSSL_QUIC_METHOD` which carries four callbacks:

* `set_encryption_secrets()`: to forward generated secrets.
* `add_handshake_data()`: to forward Handshake messages.
* `flush_flight()`: to tell the QUIC protocol handler to flush any buffered data.
* `send_alert()`: to forward SSL alerts.

A QUIC protocol handler installs these via `wolfSSL_CTX_set_quic_method()` or `wolfSSL_set_quic_method()`. When CRYPTO messages arrive from the peer, those are added via `wolfSSL_provide_quic_data()` to the `WOLFSSL*` instance:

```
  DATA ---recv+decrypt---+
                         v 
            wolfSSL_provide_quic_data(ssl, ...)
            wolfSSL_do_handshake(ssl);
                  +-> add_handshake_data_callback(REPLY)
                          |
  REPLY <--encrypt+send---+
```

The wolfSSL instance performs the common TLSv1.3 handshake processing with the significant change that it does not encrypt or decrypt messages itself. It computes all the secrets and MACs as usual, however.

Encryption and Decryption is done by the QUIC protocol handler. Which is why it gets access to the secrets
at the different encryption levels: `initial`(no encryption), `handshake`, `application` and `earlydata`.

For sending data, the level to use for encryption is a call parameter in `add_handshake_data()`. For received data, the level to use for decryption can be interrogated via `wolfSSL_quic_read_level()`.

When the handshake is done, any additional CRYPTO messages are received in the same way, only `wolfSSL_process_quic_post_handshake()` is invoked to process them.

### Crypto Support

At the basic level, there are:

* `wolfSSL_quic_get_aead()`: to get the AEAD cipher negotiated
* `wolfSSL_quic_get_md()`:  to get the MD negotiated
* `wolfSSL_quic_get_hp()`: to get the EVP_CIPHER for header protection
* `wolfSSL_quic_get_aead_tag_len()`: the get the tag length of the negotiated AEAD cipher

In addition to that, the wolfSSL QUIC API offers the following functions:

* `wolfSSL_quic_crypt_new()`: to setup a `WOLFSSL_EVP_CIPHER_CTX` for en- or decryption with AEAD cipher, key and iv.
* `wolfSSL_quic_aead_encrypt()`: to encrypt with such a context and params
* `wolfSSL_quic_aead_decrypt()`: to decrypt with such a context and params

and for key generation `wolfSSL_quic_hkdf_extract()`, `wolfSSL_quic_hkdf_expand()` and `wolfSSL_quic_hkdf()`.

## Tests

Tests have been added in `tests/quic.c` to run as part of `unit.tests`. Those go from basic checks on providing data and receiving secrets to complete handshakes between SSL client and server instances. These handshakes are done plain, with session resumption and with early data.

These tests exchange the handshake messages between the SSL instances unencrypted, verifying their sequence and contents. They also verify that client and sever did indeed generate identical secrets for the different encryption levels.




