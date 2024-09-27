NOT intended for general use!

Crafted for a specific static PSK build using an AES-CBC 128 cipher suite with
TLS 1.2 client. When compiling with the Microchip toolchain additional source
files consumed a small amount of DATA memory. psk-tls.c and psk-ssl.c are the
combination of; src/ssl.c, src/tls.c, src/internal.c, src/keys.c, src/wolfio.c,
and wolfcrypt/src/kdf.c. The code has then been trimmed for the specific use
case and adjusted to flatten the call stack. The compiler used had a limit of
around 32 function calls deep for the call stack. The linker used also was
unable to effectivily trim out unused functions, hence a lot of the unused
functions were removed in psk-tls.c and psk-ssl.c.

To build the example client using the gcc compiler run `make` from this
directory and then `./Build/example-client-psk`.
