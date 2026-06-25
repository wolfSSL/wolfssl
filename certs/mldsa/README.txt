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

Cross-level chain (tests that verification uses the verifying key's own
ML-DSA level, not the leaf's):
  mldsa87-ca-cert.pem / .der         self-signed ML-DSA-87 CA certificate
  mldsa87-ca-key.pem                 CA private key (PEM, seed-and-expanded)
  mldsa65-leaf87ca-cert.pem / .der   ML-DSA-65 leaf certificate signed by the
                                      ML-DSA-87 CA above
  mldsa65-leaf87ca-key.pem           leaf private key (PEM, seed-and-expanded)

Generated with OpenSSL 3.5+:

  openssl genpkey -algorithm ML-DSA-87 -out mldsa87-ca-key.pem
  openssl req -x509 -new -key mldsa87-ca-key.pem -days 3650 \
      -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/CN=ML-DSA-87 CA" \
      -out mldsa87-ca-cert.pem

  openssl genpkey -algorithm ML-DSA-65 -out mldsa65-leaf87ca-key.pem
  openssl req -new -key mldsa65-leaf87ca-key.pem \
      -subj "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/CN=ML-DSA-65 leaf signed by ML-DSA-87" \
      -out leaf.csr
  openssl x509 -req -in leaf.csr -CA mldsa87-ca-cert.pem \
      -CAkey mldsa87-ca-key.pem -CAcreateserial -days 3650 \
      -out mldsa65-leaf87ca-cert.pem

  openssl x509 -in mldsa87-ca-cert.pem -outform DER \
      -out mldsa87-ca-cert.der
  openssl x509 -in mldsa65-leaf87ca-cert.pem -outform DER \
      -out mldsa65-leaf87ca-cert.der
