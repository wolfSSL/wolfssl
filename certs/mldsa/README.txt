ML-DSA (FIPS 204) test key material for wolfSSL tests.

File variants, per level N in {44, 65, 87}:
  mldsa<N>_bare-seed.der    raw 32-byte seed
  mldsa<N>_seed-only.der    PKCS#8 with seed-only private key
  mldsa<N>_bare-priv.der    raw expanded private key
  mldsa<N>_priv-only.der    PKCS#8 with expanded-only private key
  mldsa<N>_seed-priv.der    PKCS#8 with seed-and-expanded private key
  mldsa<N>_oqskeypair.der   liboqs concatenated (priv || pub) format
  mldsa<N>_pub-spki.der     SubjectPublicKeyInfo wrapping the public key

Self-signed certificates and their matching keys (used by the PKCS#7/CMS
SignedData tests), per level N in {44, 65, 87}:
  mldsa<N>-cert.pem / mldsa<N>-cert.der   self-signed ML-DSA certificate
  mldsa<N>-key.pem                        matching private key (PEM,
                                          seed-and-expanded PKCS#8)
  mldsa<N>-key.der                        matching private key (DER,
                                          expanded-only PKCS#8)

The mldsa<N>-key.der files were derived from the matching mldsa<N>-key.pem
using OpenSSL 3.5+, selecting the portable expanded-only private-key shape:

  openssl pkey -in mldsa<N>-key.pem \
      -provparam ml-dsa.output_formats=priv -outform DER \
      -out mldsa<N>-key.der

Unlike the standalone mldsa<N>_priv-only.der vectors above, these correspond
to the public key in mldsa<N>-cert.der.

The *_pub-spki.der files were derived from the matching *_priv-only.der files
using OpenSSL 3.5+:

  openssl pkey -inform DER -in mldsa<N>_priv-only.der \
      -pubout -outform DER -out mldsa<N>_pub-spki.der

Regenerating the private-key variants requires producing each of the
PKCS#8 shape options explicitly; OpenSSL's default output is the
seed-and-expanded form.
