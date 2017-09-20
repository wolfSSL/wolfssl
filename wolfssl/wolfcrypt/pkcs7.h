/* pkcs7.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLF_CRYPT_PKCS7_H
#define WOLF_CRYPT_PKCS7_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_PKCS7

#ifndef NO_ASN
    #include <wolfssl/wolfcrypt/asn.h>
#endif
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifndef NO_DES3
    #include <wolfssl/wolfcrypt/des3.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* PKCS#7 content types, ref RFC 2315 (Section 14) */
enum PKCS7_TYPES {
    PKCS7_MSG                 = 650,   /* 1.2.840.113549.1.7   */
    DATA                      = 651,   /* 1.2.840.113549.1.7.1 */
    SIGNED_DATA               = 652,   /* 1.2.840.113549.1.7.2 */
    ENVELOPED_DATA            = 653,   /* 1.2.840.113549.1.7.3 */
    SIGNED_AND_ENVELOPED_DATA = 654,   /* 1.2.840.113549.1.7.4 */
    DIGESTED_DATA             = 655,   /* 1.2.840.113549.1.7.5 */
    ENCRYPTED_DATA            = 656    /* 1.2.840.113549.1.7.6 */
};

enum Pkcs7_Misc {
    PKCS7_NONCE_SZ        = 16,
    MAX_ENCRYPTED_KEY_SZ  = 512,    /* max enc. key size, RSA <= 4096 */
    MAX_CONTENT_KEY_LEN   = 32,     /* highest current cipher is AES-256-CBC */
    MAX_CONTENT_IV_SIZE   = 16,     /* highest current is AES128 */
#ifndef NO_AES
    MAX_CONTENT_BLOCK_LEN = AES_BLOCK_SIZE,
#else
    MAX_CONTENT_BLOCK_LEN = DES_BLOCK_SIZE,
#endif
    MAX_RECIP_SZ          = MAX_VERSION_SZ +
                            MAX_SEQ_SZ + ASN_NAME_MAX + MAX_SN_SZ +
                            MAX_SEQ_SZ + MAX_ALGO_SZ + 1 + MAX_ENCRYPTED_KEY_SZ
};


typedef struct PKCS7Attrib {
    byte* oid;
    word32 oidSz;
    byte* value;
    word32 valueSz;
} PKCS7Attrib;


typedef struct PKCS7DecodedAttrib {
    byte* oid;
    word32 oidSz;
    byte* value;
    word32 valueSz;
    struct PKCS7DecodedAttrib* next;
} PKCS7DecodedAttrib;


typedef struct PKCS7 {
    byte* content;                /* inner content, not owner             */
    word32 contentSz;             /* content size                         */
    int contentOID;               /* PKCS#7 content type OID sum          */

    WC_RNG* rng;

    int hashOID;
    int encryptOID;               /* key encryption algorithm OID         */
    int keyWrapOID;               /* key wrap algorithm OID               */
    int keyAgreeOID;              /* key agreement algorithm OID          */

    void*  heap;                  /* heap hint for dynamic memory         */
    byte*  singleCert;            /* recipient cert, DER, not owner       */
    word32 singleCertSz;          /* size of recipient cert buffer, bytes */
    byte issuerHash[KEYID_SIZE];  /* hash of all alt Names                */
    byte*  issuer;                /* issuer name of singleCert            */
    word32 issuerSz;              /* length of issuer name                */
    byte issuerSn[MAX_SN_SZ];     /* singleCert's serial number           */
    word32 issuerSnSz;            /* length of serial number              */

    byte publicKey[512];
    word32 publicKeySz;
    word32 publicKeyOID;          /* key OID (RSAk, ECDSAk, etc) */
    byte*  privateKey;            /* private key, DER, not owner          */
    word32 privateKeySz;          /* size of private key buffer, bytes    */

    PKCS7Attrib* signedAttribs;
    word32 signedAttribsSz;

    /* Enveloped-data optional ukm, not owner */
    byte*  ukm;
    word32 ukmSz;

    /* Encrypted-data Content Type */
    byte*        encryptionKey;         /* block cipher encryption key */
    word32       encryptionKeySz;       /* size of key buffer, bytes */
    PKCS7Attrib* unprotectedAttribs;    /* optional */
    word32       unprotectedAttribsSz;
    PKCS7DecodedAttrib* decodedAttrib;  /* linked list of decoded attribs */
} PKCS7;


WOLFSSL_API int  wc_PKCS7_Init(PKCS7* pkcs7, void* heap, int devId);
/*!
    \ingroup PKCS7
    
    \brief This function initializes a PKCS7 structure with a DER-formatted certificate. To initialize an empty PKCS7 structure, one can pass in a NULL cert and 0 for certSz. 
    
    \return 0 Returned on successfully initializing the PKCS7 structure
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity

    \param pkcs7 pointer to the PKCS7 structure in which to store the decoded cert
    \param cert pointer to a buffer containing a DER formatted ASN.1 certificate with which to initialize the PKCS7 structure
    \param certSz size of the certificate buffer
    
    _Example_
    \code
    PKCS7 pkcs7;
    byte derBuff[] = { /* initialize with DER-encoded certificate };
    if ( wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff)) != 0 ) {
    	// error parsing certificate into pkcs7 format
    }
    \endcode
    
    \sa wc_PKCS7_Free
*/
WOLFSSL_API int  wc_PKCS7_InitWithCert(PKCS7* pkcs7, byte* cert, word32 certSz);
/*!
    \ingroup PKCS7
    
    \brief This function releases any memory allocated by a PKCS7 initializer.
    
    \return none No returns.
    
    \param pkcs7 pointer to the PKCS7 structure to free
    
    _Example_
    \code
    PKCS7 pkcs7;
    // initialize and use PKCS7 object

    wc_PKCS7_Free(pkcs7);
    \endcode
    
    \sa wc_PKCS7_InitWithCert
*/
WOLFSSL_API void wc_PKCS7_Free(PKCS7* pkcs7);
/*!
    \ingroup PKCS7
    
    \brief This function builds the PKCS7 data content type, encoding the PKCS7 structure into a buffer containing a parsable PKCS7 data packet.
    
    \return Success On successfully encoding the PKCS7 data into the buffer, returns the index parsed up to in the PKCS7 structure. This index also corresponds to the bytes written to the output buffer.
    \return BUFFER_E Returned if the given buffer is not large enough to hold the encoded certificate
    
    \param pkcs7 pointer to the PKCS7 structure to encode
    \param output pointer to the buffer in which to store the encoded certificate
    \param outputSz size available in the output buffer
    
    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { /* initialize with DER-encoded certificate };
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... etc.

    ret = wc_PKCS7_EnocodeData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
	    // error encoding into output buffer
    }
    \endcode
    
    \sa wc_PKCS7_InitWithCert
*/
WOLFSSL_API int  wc_PKCS7_EncodeData(PKCS7* pkcs7, byte* output,
                                       word32 outputSz);
/*!
    \ingroup PKCS7
    
    \brief This function builds the PKCS7 signed data content type, encoding the PKCS7 structure into a buffer containing a parsable PKCS7 signed data packet.
    
    \return Success On successfully encoding the PKCS7 data into the buffer, returns the index parsed up to in the PKCS7 structure. This index also corresponds to the bytes written to the output buffer.
    \return BAD_FUNC_ARG Returned if the PKCS7 structure is missing one or more required elements to generate a signed data packet
    \return MEMORY_E Returned if there is an error allocating memory
    \return PUBLIC_KEY_E Returned if there is an error parsing the public key
    \return RSA_BUFFER_E Returned if buffer error, output too small or input too large
    \return BUFFER_E Returned if the given buffer is not large enough to hold the encoded certificate
    \return MP_INIT_E may be returned if there is an error generating the signature
    \return MP_READ_E may be returned if there is an error generating the signature
    \return MP_CMP_E may be returned if there is an error generating the signature
    \return MP_INVMOD_E may be returned if there is an error generating the signature
    \return MP_EXPTMOD_E may be returned if there is an error generating the signature
    \return MP_MOD_E may be returned if there is an error generating the signature
    \return MP_MUL_E may be returned if there is an error generating the signature
    \return MP_ADD_E may be returned if there is an error generating the signature
    \return MP_MULMOD_E may be returned if there is an error generating the signature
    \return MP_TO_E may be returned if there is an error generating the signature
    \return MP_MEM may be returned if there is an error generating the signature
    
    \param pkcs7 pointer to the PKCS7 structure to encode
    \param output pointer to the buffer in which to store the encoded certificate
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { /* initialize with DER-encoded certificate };
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... etc.

    ret = wc_PKCS7_EnocodeSignedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
    	// error encoding into output buffer
    }
    \endcode
    
    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_VerifySignedData
*/
WOLFSSL_API int  wc_PKCS7_EncodeSignedData(PKCS7* pkcs7,
                                       byte* output, word32 outputSz);
/*!
    \ingroup PKCS7
    
    \brief This function takes in a transmitted PKCS7 signed data message, extracts the certificate list and certificate revocation list, and then verifies the signature. It stores the extracted content in the given PKCS7 structure.
    
    \return 0 Returned on successfully extracting the information from the message
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid
    \return ASN_PARSE_E Returned if there is an error parsing from the given pkiMsg
    \return PKCS7_OID_E Returned if the given pkiMsg is not a signed data type
    \return ASN_VERSION_E Returned if the PKCS7 signer info is not version 1
    \return MEMORY_E Returned if there is an error allocating memory
    \return PUBLIC_KEY_E Returned if there is an error parsing the public key
    \return RSA_BUFFER_E Returned if buffer error, output too small or input too large
    \return BUFFER_E Returned if the given buffer is not large enough to hold the encoded certificate
    \return MP_INIT_E may be returned if there is an error generating the signature
    \return MP_READ_E may be returned if there is an error generating the signature
    \return MP_CMP_E may be returned if there is an error generating the signature
    \return MP_INVMOD_E may be returned if there is an error generating the signature
    \return MP_EXPTMOD_E may be returned if there is an error generating the signature
    \return MP_MOD_E may be returned if there is an error generating the signature
    \return MP_MUL_E may be returned if there is an error generating the signature
    \return MP_ADD_E may be returned if there is an error generating the signature
    \return MP_MULMOD_E may be returned if there is an error generating the signature
    \return MP_TO_E may be returned if there is an error generating the signature
    \return MP_MEM may be returned if there is an error generating the signature
    
    \param pkcs7 pointer to the PKCS7 structure in which to store the parsed certificates
    \param pkiMsg pointer to the buffer containing the signed message to verify and decode
    \param pkiMsgSz size of the signed message
    
    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { /* initialize with DER-encoded certificate };
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... etc.

    ret = wc_PKCS7_EnocodeSignedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
    	// error encoding into output buffer
    }
    \endcode
    
    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeSignedData
*/
WOLFSSL_API int  wc_PKCS7_VerifySignedData(PKCS7* pkcs7,
                                       byte* pkiMsg, word32 pkiMsgSz);
/*!
    \ingroup PKCS7
    
    \brief This function builds the PKCS7 enveloped data content type, encoding the PKCS7 structure into a buffer containing a parsable PKCS7 enveloped data packet.
    
    \return Success Returned on successfully encoding the message in enveloped data format, returns the size written to the output buffer
    \return BAD_FUNC_ARG: Returned if one of the input parameters is invalid, or if the PKCS7 structure is missing required elements
    \return ALGO_ID_E Returned if the PKCS7 structure is using an unsupported algorithm type. Currently, only DESb and DES3b are supported 
    \return BUFFER_E Returned if the given output buffer is too small to store the output data
    \return MEMORY_E Returned if there is an error allocating memory
    \return RNG_FAILURE_E Returned if there is an error initializing the random number generator for encryption
    \return DRBG_FAILED Returned if there is an error generating numbers with the random number generator used for encryption
    
    \param pkcs7 pointer to the PKCS7 structure to encode
    \param output pointer to the buffer in which to store the encoded certificate
    \param outputSz size available in the output buffer
    
    _Example_
    \code
    PKCS7 pkcs7;
    int ret;

    byte derBuff[] = { /* initialize with DER-encoded certificate };
    byte pkcs7Buff[FOURK_BUF];

    wc_PKCS7_InitWithCert(&pkcs7, derBuff, sizeof(derBuff));
    // update message and data to encode
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.content = data;
    pkcs7.contentSz = dataSz;
    ... etc.

    ret = wc_PKCS7_EncodeEnvelopedData(&pkcs7, pkcs7Buff, sizeof(pkcs7Buff));
    if ( ret != 0 ) {
    	// error encoding into output buffer
    }
    \endcode
    
    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_DecodeEnvelopedData
*/
WOLFSSL_API int  wc_PKCS7_EncodeEnvelopedData(PKCS7* pkcs7,
                                          byte* output, word32 outputSz);
/*!
    \ingroup PKCS7
    
    \brief This function unwraps and decrypts a PKCS7 enveloped data content type, decoding the message into output. It uses the private key of the PKCS7 object passed in to decrypt the message.
    
    \return On successfully extracting the information from the message, returns the bytes written to output
    \return BAD_FUNC_ARG Returned if one of the input parameters is invalid
    \return ASN_PARSE_E Returned if there is an error parsing from the given pkiMsg
    \return PKCS7_OID_E Returned if the given pkiMsg is not an enveloped data type
    \return ASN_VERSION_E Returned if the PKCS7 signer info is not version 0
    \return MEMORY_E Returned if there is an error allocating memory
    \return ALGO_ID_E Returned if the PKCS7 structure is using an unsupported algorithm type. Currently, only DESb and DES3b are supported for encryption, with RSAk for signature generation
    \return PKCS7_RECIP_E Returned if there is no recipient found in the enveloped data that matches the recipient provided
    \return RSA_BUFFER_E Returned if there is an error during RSA signature verification due to buffer error, output too small or input too large.
    \return MP_INIT_E may be returned if there is an error during signature verification
    \return MP_READ_E may be returned if there is an error during signature verification
    \return MP_CMP_E may be returned if there is an error during signature verification
    \return MP_INVMOD_E may be returned if there is an error during signature verification
    \return MP_EXPTMOD_E may be returned if there is an error during signature verification
    \return MP_MOD_E may be returned if there is an error during signature verification
    \return MP_MUL_E may be returned if there is an error during signature verification
    \return MP_ADD_E may be returned if there is an error during signature verification
    \return MP_MULMOD_E may be returned if there is an error during signature verification
    \return MP_TO_E may be returned if there is an error during signature verification
    \return MP_MEM may be returned if there is an error during signature verification
    
    \param pkcs7 pointer to the PKCS7 structure containing the private key with which to decode the enveloped data package
    \param pkiMsg pointer to the buffer containing the enveloped data package
    \param pkiMsgSz size of the enveloped data package
    \param output pointer to the buffer in which to store the decoded message
    \param outputSz size available in the output buffer

    _Example_
    \code
    PKCS7 pkcs7;
    byte received[] = { /* initialize with received enveloped message };
    byte decoded[FOURK_BUF];
    int decodedSz;

    // initialize pkcs7 with certificate
    // update key
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;

    decodedSz = wc_PKCS7_DecodeEnvelopedData(&pkcs7, received, sizeof(received),decoded, sizeof(decoded));
    if ( decodedSz != 0 ) {
    	// error decoding message
    }
    \endcode
    
    \sa wc_PKCS7_InitWithCert
    \sa wc_PKCS7_EncodeEnvelopedData
*/
WOLFSSL_API int  wc_PKCS7_DecodeEnvelopedData(PKCS7* pkcs7, byte* pkiMsg,
                                          word32 pkiMsgSz, byte* output,
                                          word32 outputSz);
WOLFSSL_API int  wc_PKCS7_EncodeEncryptedData(PKCS7* pkcs7,
                                          byte* output, word32 outputSz);
WOLFSSL_API int  wc_PKCS7_DecodeEncryptedData(PKCS7* pkcs7, byte* pkiMsg,
                                          word32 pkiMsgSz, byte* output,
                                          word32 outputSz);
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_PKCS7 */
#endif /* WOLF_CRYPT_PKCS7_H */

