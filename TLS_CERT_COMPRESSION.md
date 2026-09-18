# Time Est. of implementing compress_certificate ext. (RFC 8879)

This is an estimate of time to first iteration. My conservitive estimate is
60 hrs.

## 1. Processing compress_certificate as a valid extension ~5 - 15 hrs
```
struct {
    CertificateCompressionAlgorithm algorithms<2..2^8-2>;  /* uint16 each */
} CertificateCompressionAlgorithms;
```
Min size is 3 bytes (1-byte list length + one 2-byte algorithm).

x add build flags (configure.ac option, CMake option, cmake/options.h.in)
x add TLSXT_COMPRESS_CERTIFICATE (0x001b) define and TLSX_Type enum entry in
internal.h (27 <= SEMAPHORE_MAX_DIRECT_TYPE, so no TLSX_ToSemaphore change)
x add TLSX logic to handle
    x parsing
    x using
x add to TLSX_FreeAll
x add to TLSX_GetSize
x add to TLSX_Write
x add to TLSX_Parse
x add to TLSX_GetMinSize_Client/Server
x add to TLSX_CustomExt_IsKnown
x define min sizes
x add to ClientHello (client)
x add to CertificateRequest (server), including a TURN_OFF for the extension in
the certificate_request branch of TLSX_GetRequestSize (the semaphore starts as
0xff there, so it is never sent otherwise)
x TLSX_PopulateExtensions
x write tests to assert that extension is processed and does not accept
malformed extension value

## 2. compress the cert ~ 15 - 25 hrs
```
struct {
     CertificateCompressionAlgorithm algorithm; /* uint16 */
     uint24 uncompressed_length;
     opaque compressed_certificate_message<1..2^24-1>;
} CompressedCertificate;
```
- add compressed_certificate (25) handshake message type
- switch on if we compress cert or not where certs are added to the message
- SendTls13Certificate writes the body in fragments straight into the output
buffer; we need to compress before writing to output buffer.
- compress certs
- build compressed cert message
- make sure to hash the compressed cert message
- add tests to assert that built message is formed correctly before sending
if possible otherwise put off to handshake tests


## 3. decompress the cert ~ 15 - 20 hrs
```
struct {
     CertificateCompressionAlgorithm algorithm; /* uint16 */
     uint24 uncompressed_length;
     opaque compressed_certificate_message<1..2^24-1>;
} CompressedCertificate;
```
- add compressed_certificate dispatch and message order/sanity checks in
tls13.c
- switch on if we get the compressed cert message or if we get the normal cert
message
- reject a CompressedCertificate that uses an algorithm we did not offer
alert
- check that uncompressed_length is not bigger than our set max (may be lower
than RFC max, e.g. MAX_CERTIFICATE_SZ) before allocating
- decompress cert with agreed compression alg
- check the decompressed size matches uncompressed_length exactly
- decompression failure or length mismatch aborts with a bad_certificate alert
- add tests to assert that malformed compression is handled properly and
that if the ext is ignored we can fallback to uncompressed certs handling
for both client and server

## Overarching considerations
- only compile in relevant code when TLS 1.3 and a compression backend are
enabled
- set up benchmark tests asap to ensure performance issues are caught early
- experiment with best defaults for zlib

## Extra Features adds more time.
- The first iteration will only support zlib (via HAVE_LIBZ). We can create
bindings for brotli and zstd, or add compression callbacks for other or custom
compression defined by users

- Add compressed Cert caching to not have to repeat compression. Only valid
when the request context is empty (not post-handshake auth) and no
per-certificate extensions (e.g. an OCSP staple) are sent. Adds complexity but
could cut down on latency if a server is doing a ton of compressed cert sending
to new connections. Could be worth measuring.

just doing a plain memcopy is 1400x faster than compression so could be worth
it

