/*!
    \ingroup ASN

    \brief This function extracts the subject public key from a C509
    certificate (draft-ietf-cose-cbor-encoded-cert, the compact CBOR encoding
    of an X.509 certificate). The raw key bytes are written to out and the key
    type is reported through keyType. Available with --enable-c509
    (WOLFSSL_C509).

    \note This reads only the subjectPublicKey; it does not check the
    c509CertificateType field or validate the rest of the certificate, so it
    succeeds on a type-2 or type-3 certificate alike. On BUFFER_E no required
    size is reported - size out for the largest key in use (an RSA modulus, or
    132 bytes for an EC X||Y). It uses the default heap; use
    wc_C509_GetPubKeyEx to supply a heap hint for the internal EC
    point-decompression key.

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned if c509, out or outLen is NULL, or c509Sz is
    0.
    \return ASN_PARSE_E Returned if the C509 certificate is malformed.
    \return BUFFER_E Returned if out is too small for the key.
    \return ASN_UNKNOWN_OID_E Returned if the subject public key is in an
    unsupported form: an unsupported or compiled-out key algorithm (e.g. a
    bare-modulus RSA key when RSA is compiled out), an OID-identified
    (non-codepoint) subjectPublicKeyAlgorithm, an unsupported curve, or a
    compressed EC point when point decompression is not available.
    \return ASN_PARSE_E Returned if the certificate is malformed, including - when
    RSA is compiled out (NO_RSA) - an RSA (codepoint 0) subjectPublicKey in the
    [modulus, exponent] array form: with no RSA array handling it is read as a
    plain byte string, which an array is not. (A bare-modulus RSA key under
    NO_RSA instead returns ASN_UNKNOWN_OID_E, as above.)
    \return NOT_COMPILED_IN Returned for an RSA [modulus, exponent] array whose
    exponent is not 65537 (when RSA is built in).
    \return MEMORY_E Returned if an internal allocation for compressed EC point
    decompression fails (on WOLFSSL_SMALL_STACK builds). Compressed-point
    decompression may also pass through another wolfCrypt error (for example for
    a point that is not on the curve).

    \param [in] c509 C509 certificate bytes.
    \param [in] c509Sz Length of c509.
    \param [out] out Buffer receiving the raw subject public key: Edwards keys
    raw (Ed25519 32, Ed448 57), Weierstrass EC keys as X||Y (secp256r1 /
    brainpoolP256r1 64, secp384r1 / brainpoolP384r1 96, secp521r1 132,
    brainpoolP512r1 128), and for RSA the modulus bytes only. A C509 RSA public
    key may be a bare modulus (public exponent 65537 assumed) or a
    [modulus, exponent] array; the array form is accepted only when its exponent
    equals 65537, and any other exponent returns NOT_COMPILED_IN (so a caller
    that gets 0 may always assume exponent 65537). A compressed EC point (the
    SECG 0x02/0x03 form of a native C509 key, or the 0xfe/0xfd type-3 marker,
    || X) is decompressed to X||Y when built with HAVE_ECC and HAVE_COMP_KEY.
    \param [in,out] outLen On input the capacity of out; on output the number
    of key bytes written.
    \param [out] keyType Optional; receives a wc_C509_KeyType value
    (WC_C509_KEY_ED25519, WC_C509_KEY_ED448, WC_C509_KEY_P256/P384/P521,
    WC_C509_KEY_BP256/BP384/BP512 or WC_C509_KEY_RSA). May be NULL.

    _Example_
    \code
    byte   key[256]; // 256 covers up to RSA-2048 and all supported EC curves
    word32 keyLen = sizeof(key);
    int    keyType;

    if (wc_C509_GetPubKey(cert, certSz, key, &keyLen, &keyType) == 0) {
        // key/keyLen hold the raw subject public key
    }
    \endcode

    \sa wc_C509_GetPubKeyEx
    \sa wc_C509_Verify
    \sa wc_C509_ToDer
*/
WOLFSSL_API int wc_C509_GetPubKey(const byte* c509, word32 c509Sz,
    byte* out, word32* outLen, int* keyType);

/*!
    \ingroup ASN

    \brief This function reconstructs the DER X.509 certificate encoded in a
    type-3 C509 certificate. A type-3 C509 is a CBOR re-encoding of a DER
    X.509 certificate whose signature is over the original DER
    TBSCertificate, so this rebuilds the byte-exact DER so that signature can
    be verified. Only type 3 is supported (a type-2 certificate is natively
    CBOR-signed and has no DER equivalent). Supported subject public keys /
    signature algorithms are ECDSA over the NIST and brainpool curves
    (SHA-256/384/512 or SHAKE128/256, uncompressed or - with HAVE_COMP_KEY -
    compressed points that are decompressed), RSA (only sha256WithRSAEncryption,
    i.e. RSA PKCS#1 v1.5 with SHA-256; RSA-SHA384, RSA-SHA512 and RSASSA-PSS are
    not supported for type 3 and return NOT_COMPILED_IN) and Ed25519 / Ed448.
    For issuer/subject Names the registered attributes commonName, surname,
    countryName, title, givenName and name (C509 attribute codepoints 1, 2, 4,
    10, 13 and 25) are reconstructed; the codepoint's sign selects the DER
    value-string type, a positive codepoint giving a UTF8String and a negative
    codepoint the same attribute (by absolute value) as a PrintableString (the
    form a real X.509 Name uses for countryName, and legacy certificates for
    others). An OID-identified (~oid) name attribute is instead reconstructed
    with its DER value verbatim, whatever ASN.1 string type that value carries.
    It also
    covers UTCTime and GeneralizedTime validity (including the RFC 5280
    no-expiry 99991231235959Z date), the SubjectKeyIdentifier, the
    AuthorityKeyIdentifier (the keyIdentifier byte-string form only - the
    [keyId, certIssuer, serial] array form returns NOT_COMPILED_IN), KeyUsage
    (both the array form and the compact single-KeyUsage int form, whose sign
    marks it critical), BasicConstraints (with pathLenConstraint),
    ExtendedKeyUsage and SubjectAltName extensions (including the C509
    single-dNSName shortcut carried as a bare text string), and unregistered
    (OID-identified) extensions. ExtendedKeyUsage covers only the serverAuth and
    clientAuth purposes. Everything else returns NOT_COMPILED_IN: any other
    registered name attribute (e.g. organizationName, organizationalUnitName,
    localityName, stateOrProvinceName), any other EKU purpose, a non-text
    (e.g. byte-string) value on a registered (codepoint) attribute, and a
    CBOR-tagged (EUI-64/MAC) name, as well as the other registered compact
    extension forms (e.g. RFC 3779 IPAddrBlocks). The whole
    function returns NOT_COMPILED_IN when built with WOLFSSL_C509_NO_TYPE3
    (--disable-c509-type3 / CMake -DWOLFSSL_C509_TYPE3=no). Available with
    --enable-c509 (WOLFSSL_C509).

    \note A type-3 certificate does NOT have a single canonical C509 encoding:
    the reconstruction accepts several application-level alternatives that
    rebuild identical DER (the compact KeyUsage int versus the [codepoint,
    value] array, a single-dNSName SAN as bare text versus [2, text], an EKU as
    a bare int versus a one-element array, an uncompressed point versus a
    compressed one), so a third party can re-encode a type-3 certificate into
    different C509 bytes that still verify. A relying party that pins,
    blocklists or deduplicates type-3 certificates MUST key on the hash of this
    function's reconstructed DER output, not on the C509 bytes. (A type-2
    certificate with a deterministic signature - RSA PKCS#1 v1.5, Ed25519 or
    Ed448 - is byte-unique; a type-2 ECDSA certificate is not, since ECDSA is
    malleable - (r, s) and (r, n-s) both verify.)

    \return 0 Returned on success (out non-NULL).
    \return LENGTH_ONLY_E Returned when out is NULL: *outLen is set to the
    required DER length and nothing is written (the wolfSSL size-query
    convention). The structure is still validated, so a malformed or
    out-of-profile certificate returns its usual error instead - with one
    exception: a compressed EC subjectPublicKey is only length-reserved, not
    decompressed, in a size query, so its per-curve length and on-curve validity
    are checked only when out is non-NULL. A size query can therefore return the
    length for a certificate whose compressed point the real call rejects
    (ASN_UNKNOWN_OID_E or a wolfCrypt ECC error).
    \return BAD_FUNC_ARG Returned if c509 or outLen is NULL, c509Sz is 0, or the
    certificate is not type 3.
    \return ASN_PARSE_E Returned if the C509 certificate is malformed.
    \return ASN_UNKNOWN_OID_E Returned (out non-NULL) for an unsupported
    compressed EC point - an unsupported curve or a point whose length exceeds
    the SEC1 buffer.
    \return BUFFER_E Returned if out is too small for the reconstructed DER, or -
    on any build, even for a size query - if a single reconstructed DER element
    is 65536 bytes or larger (the 64 KB DER length limit).
    \return NOT_COMPILED_IN Returned for a field or profile the reconstruction
    does not cover, or when the build compiled type-3 support out
    (WOLFSSL_C509_NO_TYPE3).
    \return MEMORY_E Returned if an internal allocation fails (on
    WOLFSSL_SMALL_STACK builds, e.g. during compressed-point decompression).
    Compressed-point decompression may also pass through another wolfCrypt
    error (for example for a point that is not on the curve).

    \param [in] c509 C509 certificate bytes (type 3).
    \param [in] c509Sz Length of c509.
    \param [out] out Buffer receiving the reconstructed DER certificate, or NULL
    to query the required length (returns LENGTH_ONLY_E). On any error - every
    path, including the NULL-c509/zero-size BAD_FUNC_ARG and the NOT_COMPILED_IN
    of a WOLFSSL_C509_NO_TYPE3 build - the output buffer is cleared, as long as
    out and outLen are both non-NULL (a NULL out has nothing to clear).
    \param [in,out] outLen When out is non-NULL, on input the capacity of out
    and on output the DER length written, or 0 on any error (uniformly, when
    outLen is non-NULL). When out is NULL, receives the required DER length.
    BUFFER_E does not report the size needed; query it with a NULL out (exact for
    any certificate the real call accepts - but see LENGTH_ONLY_E on the
    compressed-point caveat), or size out at WC_C509_MAX_DER (the derived default
    that fits the profiles the tests cover).

    _Example_
    \code
    byte   der[1024];
    word32 derLen = sizeof(der);

    if (wc_C509_ToDer(cert, certSz, der, &derLen) == 0) {
        // der/derLen hold the reconstructed X.509 certificate
    }

    // size query: out == NULL returns LENGTH_ONLY_E with the needed length
    word32 needed = 0;
    if (wc_C509_ToDer(cert, certSz, NULL, &needed) == LENGTH_ONLY_E) {
        // needed is the reconstructed DER length
    }
    \endcode

    \sa wc_C509_Verify
    \sa wc_C509_GetPubKey
*/
WOLFSSL_API int wc_C509_ToDer(const byte* c509, word32 c509Sz,
    byte* out, word32* outLen);

/*!
    \ingroup ASN

    \brief This function verifies ONLY the issuer signature of a C509
    certificate with the issuer's raw public key. It does not validate the
    validity period, basicConstraints/cA, keyUsage, issuer-name chaining or
    revocation; a return of 0 means the signature is valid, not that the
    certificate is trusted, and the caller owns any policy and chain checks. For
    a type-2 (natively signed) certificate the signature is checked over the
    CBOR TBSCertificate; for a type-3 (CBOR re-encoded X.509) certificate the
    DER TBSCertificate is reconstructed and the signature verified over it using
    the same per-algorithm check as the type-2 path, so ECDSA (ES256/ES384/ES512
    and the SHAKE128/256 variants), RSA, Ed25519 and Ed448 all verify for both
    certificate types. This function infers the issuer key type from the
    signature algorithm, so it cannot be used where that inference is ambiguous:
    it returns BAD_FUNC_ARG for an RSA signature-algorithm codepoint, and the
    caller MUST use wc_C509_VerifyEx with WC_C509_KEY_RSA for an RSA issuer -
    the same requirement the ecdsa-with-SHAKE128/256 algorithms already have.
    (An inferred key type cannot tell a real RSA modulus from a large EC X||Y,
    so RSA must be named explicitly.) Type-3 RSA moreover supports only
    sha256WithRSAEncryption. A brainpool issuer key (brainpoolP256r1,
    brainpoolP384r1 or brainpoolP512r1) cannot be used here: with an inferred
    key type ES256/ES384/ES512 always select the NIST curve (secp256r1 /
    secp384r1 / secp521r1), so a brainpool issuer MUST use wc_C509_VerifyEx with
    its WC_C509_KEY_BP256/BP384/BP512 key type. Available with --enable-c509
    (WOLFSSL_C509).

    \note To read a type-3 certificate's extensions (keyUsage, extKeyUsage,
    basicConstraints, ...), parse the DER produced by wc_C509_ToDer with an
    ordinary X.509 parser - never scan the C509 CBOR directly. The draft allows
    an extension that has a registered integer codepoint to also be carried in
    OID form; both rebuild to the same signed DER, so the signature verifies
    either way, but a consumer that only recognised int codepoints would miss an
    OID-form extension that the reconstructed certificate does contain.

    \return 0 Returned when the signature is valid.
    \return ASN_SIG_CONFIRM_E Returned when the signature does not verify.
    \return BAD_FUNC_ARG Returned if issuerPub or c509 is NULL, c509Sz is 0,
    if issuerPubSz does not match the certificate's signature algorithm, or if
    the certificate names a signature-algorithm codepoint whose key type cannot
    be inferred - an RSA codepoint or an ecdsa-with-SHAKE128/256 codepoint (the
    SHAKE codepoint does not fix the curve); use wc_C509_VerifyEx with
    WC_C509_KEY_RSA or the EC key type respectively.
    \return ASN_PARSE_E Returned if the C509 certificate is malformed, including
    an ECDSA issuerSignatureValue that is not the RFC 9053 Section 2.1 fixed
    per-curve width (r and s each padded to the coordinate size, e.g. 64 bytes
    total for P-256, 132 for P-521; a shorter or longer r||s is rejected), and
    an Ed25519 or Ed448 issuerSignatureValue that is not the fixed signature
    length (64 and 114 bytes).
    \return BUFFER_E Returned, on a no-dynamic-allocation build, if a type-3
    certificate's reconstructed DER exceeds the fixed WC_C509_MAX_DER buffer (a
    WOLFSSL_SMALL_STACK build sizes that buffer exactly, so it does not return
    BUFFER_E for an oversized type-3 certificate there), and on ANY build if a
    single reconstructed DER element is 65536 bytes or larger (the 64 KB DER
    length limit).
    \return MEMORY_E Returned if an internal allocation fails (on
    WOLFSSL_SMALL_STACK builds).
    \return NOT_COMPILED_IN Returned if the signature algorithm is not supported
    in this build, for a type-3 field or profile the reconstruction does not
    cover, or for any type-3 certificate when type-3 support is compiled out
    (WOLFSSL_C509_NO_TYPE3).
    \return <0 Other negative wolfCrypt error codes from the underlying key
    import or signature check pass through unchanged (for example a malformed
    issuer key, the Ed448 context-length range check, or an RSA input-length
    error).

    \param [in] issuerPub Raw issuer public key matching the certificate's
    signature algorithm - ECDSA with SHA-256/384/512 (NIST P-256/384/521),
    RSA PKCS#1 v1.5 or RSASSA-PSS with SHA-256/384/512, Ed25519 or Ed448
    (Ed25519 32, Ed448 57, ECDSA as X||Y: P-256 64, P-384 96, P-521 132, RSA as
    the modulus with public exponent assumed 65537). RSA issuers and ECDSA with
    SHAKE128/256 signatures need wc_C509_VerifyEx (RSA because the key type must
    be named, SHAKE because the codepoint does not fix the curve).
    \param [in] issuerPubSz Length of issuerPub.
    \param [in] c509 C509 certificate bytes.
    \param [in] c509Sz Length of c509.

    _Example_
    \code
    // issuer key obtained out of band or from the issuer's certificate
    if (wc_C509_Verify(issuerPub, issuerPubSz, cert, certSz) == 0) {
        // the certificate signature is valid
    }
    \endcode

    \sa wc_C509_VerifyEx
    \sa wc_C509_VerifyEx2
    \sa wc_C509_GetPubKey
    \sa wc_C509_ToDer
*/
WOLFSSL_API int wc_C509_Verify(const byte* issuerPub, word32 issuerPubSz,
    const byte* c509, word32 c509Sz);

/*!
    \ingroup ASN

    \brief This function verifies the issuer signature of a C509 certificate,
    with the issuer key type supplied so a brainpool key can be distinguished
    from the wire-identical NIST curve of the same strength. It behaves like
    wc_C509_Verify but takes a keyType (a wc_C509_KeyType, typically the value
    wc_C509_GetPubKey reported for the issuer's own certificate). It is also
    required for the ecdsa-with-SHAKE128/256 signature algorithms, whose
    codepoint fixes only the hash (RFC 8692), so the curve comes from keyType.
    keyType applies to BOTH type-2 and type-3 certificates: type-3 ECDSA
    verification now threads keyType through to pick the curve for the
    reconstructed-DER signature check, so a brainpool or SHAKE type-3 issuer is
    handled as well. Available with --enable-c509 (WOLFSSL_C509).

    \return 0 Returned when the signature is valid.
    \return ASN_SIG_CONFIRM_E Returned when the signature does not verify.
    \return BAD_FUNC_ARG Returned if issuerPub or c509 is NULL, c509Sz is 0,
    keyType is outside the wc_C509_KeyType range, issuerPubSz does not match
    the certificate's signature algorithm, keyType is a valid value whose
    algorithm family does not match the certificate's signature algorithm (for
    example WC_C509_KEY_RSA against an ECDSA certificate - this returns
    BAD_FUNC_ARG, not ASN_SIG_CONFIRM_E), or the RSA modulus is shorter than
    WC_C509_RSA_MIN_BITS (1024 bits by default; a hardened build raises it to
    2048 under WOLFSSL_HARDEN_TLS or 3072 under WOLFSSL_MAX_STRENGTH, and it can
    be overridden directly).
    \return ASN_PARSE_E Returned if the C509 certificate is malformed, including
    an ECDSA issuerSignatureValue that is not the RFC 9053 Section 2.1 fixed
    per-curve width (r and s each padded to the coordinate size, e.g. 64 bytes
    total for P-256, 132 for P-521; a shorter or longer r||s is rejected), and
    an Ed25519 or Ed448 issuerSignatureValue that is not the fixed signature
    length (64 and 114 bytes).
    \return BUFFER_E Returned if a type-2 RSA signature is longer than
    WC_C509_MAX_DER; on a no-dynamic-allocation build if a type-3 certificate's
    reconstructed DER exceeds the fixed WC_C509_MAX_DER buffer (a
    WOLFSSL_SMALL_STACK build sizes that buffer exactly, so an oversized type-3
    certificate does not return BUFFER_E there); and on ANY build if a single
    reconstructed DER element is 65536 bytes or larger (the 64 KB DER length
    limit).
    \return MEMORY_E Returned if an internal allocation fails (on
    WOLFSSL_SMALL_STACK builds).
    \return NOT_COMPILED_IN Returned if the signature algorithm is not supported
    in this build (including type-3 RSA other than sha256WithRSAEncryption), for
    a type-3 field or profile the reconstruction does not cover, or for any
    type-3 certificate when type-3 support is compiled out
    (WOLFSSL_C509_NO_TYPE3).
    \return <0 Other negative wolfCrypt error codes from the underlying key
    import or signature check pass through unchanged (for example a malformed
    issuer key, the Ed448 context-length range check, or an RSA input-length
    error).

    \param [in] issuerPub Raw issuer public key (see wc_C509_Verify).
    \param [in] issuerPubSz Length of issuerPub.
    \param [in] keyType Issuer key type (a wc_C509_KeyType);
    WC_C509_KEY_BP256/BP384/BP512 selects a brainpool curve. WC_C509_KEY_UNKNOWN
    infers only NIST-curve ECDSA (ES256/ES384/ES512 over secp256r1/384r1/521r1)
    and Ed25519/Ed448; it returns BAD_FUNC_ARG for an RSA signature-algorithm
    codepoint and for an ecdsa-with-SHAKE128/256 codepoint (neither key type can
    be inferred - name the key type to verify those). An out-of-range value
    returns BAD_FUNC_ARG.
    \param [in] c509 C509 certificate bytes.
    \param [in] c509Sz Length of c509.

    _Example_
    \code
    byte   issuerPub[256];
    word32 issuerPubSz = sizeof(issuerPub);
    int    keyType;

    // issuer key + type from the issuer's certificate
    if (wc_C509_GetPubKey(issuerCert, issuerCertSz, issuerPub, &issuerPubSz,
            &keyType) != 0) {
        // handle error
    }
    if (wc_C509_VerifyEx(issuerPub, issuerPubSz, keyType, cert, certSz) == 0) {
        // signature authenticates; the caller must still check the validity
        // period, basicConstraints/keyUsage and issuer-name chaining
    }
    \endcode

    \sa wc_C509_Verify
    \sa wc_C509_VerifyEx2
    \sa wc_C509_GetPubKey
*/
WOLFSSL_API int wc_C509_VerifyEx(const byte* issuerPub, word32 issuerPubSz,
    int keyType, const byte* c509, word32 c509Sz);

/*!
    \ingroup ASN

    \brief This function is wc_C509_VerifyEx with an additional heap hint and
    device id. heap is threaded into every internal allocation on the verify
    path (the issuer RsaKey / ecc_key / ed25519_key / ed448_key, the scratch
    buffers and the type-3 reconstruction buffer - which on a WOLFSSL_SMALL_STACK
    build is sized exactly from the certificate, so a type-3 certificate verifies
    with no WC_C509_MAX_DER cap, as long as each reconstructed DER element is
    within the 64 KB DER length limit), and devId into the issuer
    signature-verify key objects, so the issuer-key import and the signature
    check can draw from a WOLFSSL_STATIC_MEMORY pool and/or run on a
    crypto-callback device (PKCS#11, a secure element). devId is deliberately
    NOT applied to the EC point-decompression scratch key (a public-point local
    operation) nor to the one-shot TBS message hash (wc_Sha*Hash takes no
    heap/devId). wc_C509_VerifyEx is exactly this call with heap == NULL and
    devId == INVALID_DEVID. This is the entry point for the constrained /
    offloaded targets C509 serves. Available with --enable-c509 (WOLFSSL_C509).

    \return 0 Returned when the signature is valid.
    \return ASN_SIG_CONFIRM_E Returned when the signature does not verify.
    \return BAD_FUNC_ARG As for wc_C509_VerifyEx (NULL/zero args, an
    out-of-range keyType, a keyType/algorithm family mismatch, an inferred RSA
    codepoint, or an issuerPubSz that does not match the algorithm).
    \return ASN_PARSE_E Returned for a malformed certificate, including a
    wrong-length EdDSA signatureValue (as wc_C509_VerifyEx).
    \return BUFFER_E Returned for a type-2 RSA signature longer than
    WC_C509_MAX_DER; on a no-dynamic-allocation build for a type-3
    reconstruction that exceeds the fixed WC_C509_MAX_DER buffer (as
    wc_C509_VerifyEx; a WOLFSSL_SMALL_STACK build sizes the reconstruction
    buffer exactly from the certificate); and on ANY build for a single
    reconstructed DER element of 65536 bytes or more (the 64 KB DER length
    limit).
    \return NOT_COMPILED_IN Returned for an unsupported algorithm / field, or a
    type-3 certificate in a WOLFSSL_C509_NO_TYPE3 build (as wc_C509_VerifyEx).
    \return MEMORY_E Returned if an internal allocation fails (on
    WOLFSSL_SMALL_STACK builds).
    \return <0 Other negative wolfCrypt codes from the key import or signature
    check pass through unchanged (as wc_C509_VerifyEx).

    \param [in] issuerPub Raw issuer public key (see wc_C509_Verify).
    \param [in] issuerPubSz Length of issuerPub.
    \param [in] keyType Issuer wc_C509_KeyType (see wc_C509_VerifyEx).
    \param [in] c509 C509 certificate bytes.
    \param [in] c509Sz Length of c509.
    \param [in] heap Heap hint passed to the internal allocations and key
    objects (may be NULL for the default heap).
    \param [in] devId Device id passed to the issuer signature-verify key
    object (INVALID_DEVID for software crypto).

    _Example_
    \code
    // verify using a static-memory pool and a registered crypto-callback
    // device (heap is the pool hint, devId the registered device id)
    if (wc_C509_VerifyEx2(issuerPub, issuerPubSz, WC_C509_KEY_P256, cert,
            certSz, myHeap, myDevId) == 0) {
        // the certificate signature is valid
    }
    \endcode

    \sa wc_C509_VerifyEx
    \sa wc_C509_Verify
*/
WOLFSSL_API int wc_C509_VerifyEx2(const byte* issuerPub, word32 issuerPubSz,
    int keyType, const byte* c509, word32 c509Sz, void* heap, int devId);

/*!
    \ingroup ASN

    \brief This function is wc_C509_GetPubKey with an additional heap hint for
    the internal EC point-decompression key (used only when the
    subjectPublicKey is a compressed point), so the extraction can draw from a
    WOLFSSL_STATIC_MEMORY pool. There is no devId parameter: the only crypto in
    this call is public-point decompression, which is never routed to a
    crypto-callback device. wc_C509_GetPubKey is exactly this call with
    heap == NULL. Available with --enable-c509 (WOLFSSL_C509).

    \return 0 Returned on success.
    \return BAD_FUNC_ARG Returned if c509, out or outLen is NULL, or c509Sz is 0
    (as wc_C509_GetPubKey).
    \return ASN_PARSE_E Returned if the certificate is malformed.
    \return BUFFER_E Returned if out is too small for the key.
    \return ASN_UNKNOWN_OID_E Returned for an unsupported subject-public-key
    algorithm or point form.
    \return NOT_COMPILED_IN Returned for an RSA key whose exponent is not 65537.
    \return MEMORY_E Returned if an internal allocation fails (on
    WOLFSSL_SMALL_STACK builds). Decompressing a compressed EC point may also
    pass through another wolfCrypt error (for example a point not on the curve).

    \param [in] c509 C509 certificate bytes.
    \param [in] c509Sz Length of c509.
    \param [out] out Buffer receiving the raw subject public key.
    \param [in,out] outLen On input the capacity of out; on output the key
    length written.
    \param [out] keyType Optional; receives the wc_C509_KeyType (may be NULL).
    \param [in] heap Heap hint for the decompression key (may be NULL for the
    default heap).

    _Example_
    \code
    // extract a compressed-point issuer key into a static-memory pool
    byte   key[64];
    word32 keyLen = sizeof(key);
    int    keyType = 0;
    if (wc_C509_GetPubKeyEx(cert, certSz, key, &keyLen, &keyType,
            myHeap) == 0) {
        // key holds the raw subject public key
    }
    \endcode

    \sa wc_C509_GetPubKey
*/
WOLFSSL_API int wc_C509_GetPubKeyEx(const byte* c509, word32 c509Sz,
    byte* out, word32* outLen, int* keyType, void* heap);
