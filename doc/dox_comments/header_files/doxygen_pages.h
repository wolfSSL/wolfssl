/*!
    \page wolfssl_API wolfSSL API Reference
    - \ref CertManager
    - \ref Memory
    - \ref openSSL

    - \ref CertsKeys
    - \ref IO
    - \ref Setup
    - \ref Debug
    - \ref TLS
*/
/*!
    \page wolfcrypt_API wolfCrypt API Reference
    <ul>
        <li>\ref ASN</li>
        <li>\ref Base_Encoding</li>
        <li>\ref Compression</li>
        <li>\ref Error</li>
        <li>\ref IoTSafe</li>
        <li>\ref PSA</li>
        <li>\ref Keys</li>
        <li>\ref Logging</li>
        <li>\ref Math</li>
        <li>\ref Random</li>
        <li>\ref Signature</li>
        <li>\ref wolfCrypt</li>
    </ul>
    <ul>
        <li>\ref DES</li>
        <li>\ref AES</li>
        <li>\ref ARC4</li>
        <li>\ref BLAKE2</li>
        <li>\ref Camellia</li>
        <li>\ref ChaCha</li>
        <li>\ref ChaCha20Poly1305</li>
        <li>\ref CMAC</li>
        <li>\ref Crypto Callbacks</li>
        <li>\ref Curve25519</li>
        <li>\ref Curve448</li>
        <li>\ref DSA</li>
        <li>\ref Diffie-Hellman</li>
        <li>\ref ECC</li>
        <li>\ref ED25519</li>
        <li>\ref ED448</li>
        <li>\ref ECCSI</li>
        <li>\ref SAKKE</li>
        <li>\ref HMAC</li>
        <li>\ref MD2</li>
        <li>\ref MD4</li>
        <li>\ref MD5</li>
        <li>\ref Password</li>
        <li>\ref PKCS7</li>
        <li>\ref PKCS11</li>
        <li>\ref Poly1305</li>
        <li>\ref RIPEMD</li>
        <li>\ref RSA</li>
        <li>\ref SHA</li>
        <li>\ref SipHash</li>
        <li>\ref SrtpKdf</li>
        <li>\ref SRP</li>
    </ul>
*/
/*!
    \page ECCSI ECCSI API Reference
    - \ref ECCSI_Overview
    - \ref ECCSI_Setup
    - \ref ECCSI_Operations
*/
/*!
    \page SAKKE SAKKE API Reference
    - \ref SAKKE_Overview
    - \ref SAKKE_Setup
    - \ref SAKKE_RSK
    - \ref SAKKE_Operations
*/
/*!
    \page AES_CryptoCB_KeyImport AES CryptoCB Key Import

    When enabled via WOLF_CRYPTO_CB_AES_SETKEY, wolfSSL invokes a CryptoCB
    callback during AES key setup. The callback behavior determines the mode:

    **If callback returns 0 (success):**
    - Key is imported to Secure Element/HSM
    - Key is NOT copied to wolfSSL RAM (true key isolation)
    - GCM tables are NOT generated (full hardware offload)
    - All subsequent AES operations route through CryptoCB

    **If callback returns CRYPTOCB_UNAVAILABLE:**
    - SE doesn't support key import
    - Normal software AES path is used
    - Key is copied to devKey for CryptoCB encrypt/decrypt acceleration

    This mode is compatible with Secure Elements and hardware-backed
    key storage and is intended for protecting TLS traffic keys.

    \sa wc_CryptoCb_AesSetKey
    \sa \ref Crypto Callbacks
*/

