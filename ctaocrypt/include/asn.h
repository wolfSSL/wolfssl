/* asn.h
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifndef CTAO_CRYPT_ASN_H
#define CTAO_CRYPT_ASN_H

#include "types.h"
#include "ctc_rsa.h"
#include "ctc_dh.h"
#include "ctc_dsa.h"
#include "ctc_sha.h"
#ifdef HAVE_ECC
    #include "ctc_ecc.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif


enum {
    ISSUER  = 0,
    SUBJECT = 1,

    BEFORE  = 0,
    AFTER   = 1
};

/* ASN Tags   */
enum ASN_Tags {        
    ASN_INTEGER           = 0x02,
    ASN_BIT_STRING        = 0x03,
    ASN_OCTET_STRING      = 0x04,
    ASN_TAG_NULL          = 0x05,
    ASN_OBJECT_ID         = 0x06,
    ASN_SEQUENCE          = 0x10,
    ASN_SET               = 0x11,
    ASN_UTC_TIME          = 0x17,
    ASN_GENERALIZED_TIME  = 0x18,
    ASN_LONG_LENGTH       = 0x80
};


enum  ASN_Flags{
    ASN_CONSTRUCTED       = 0x20,
    ASN_CONTEXT_SPECIFIC  = 0x80
};

enum DN_Tags {
    ASN_COMMON_NAME   = 0x03,   /* CN */
    ASN_SUR_NAME      = 0x04,   /* SN */
    ASN_COUNTRY_NAME  = 0x06,   /* C  */
    ASN_LOCALITY_NAME = 0x07,   /* L  */
    ASN_STATE_NAME    = 0x08,   /* ST */
    ASN_ORG_NAME      = 0x0a,   /* O  */
    ASN_ORGUNIT_NAME  = 0x0b    /* OU */
};

enum Misc_ASN { 
    ASN_NAME_MAX        = 256,    
    SHA_SIZE            =  20,
    RSA_INTS            =   8,     /* RSA ints in private key */
    MIN_DATE_SIZE       =  13,
    MAX_DATE_SIZE       =  32,
    ASN_GEN_TIME_SZ     =  15,     /* 7 numbers * 2 + Zulu tag */
    MAX_ENCODED_SIG_SZ  = 512,
    MAX_SIG_SZ          = 256,
    MAX_ALGO_SZ         =  20,
    MAX_SEQ_SZ          =   5,     /* enum(seq | con) + length(4) */  
    MAX_SET_SZ          =   5,     /* enum(set | con) + length(4) */  
    MAX_VERSION_SZ      =   5,     /* enum + id + version(byte) + (header(2))*/
    MAX_ENCODED_DIG_SZ  =  25,     /* sha + enum(bit or octet) + legnth(4) */
    MAX_RSA_INT_SZ      = 517,     /* RSA raw sz 4096 for bits + tag + len(4) */
    MAX_NTRU_KEY_SZ     = 610,     /* NTRU 112 bit public key */
    MAX_NTRU_ENC_SZ     = 628,     /* NTRU 112 bit DER public encoding */
    MAX_RSA_E_SZ        =  16,     /* Max RSA public e size */
    MAX_PUBLIC_KEY_SZ   = MAX_NTRU_ENC_SZ + MAX_ALGO_SZ + MAX_SEQ_SZ * 2, 
                                   /* use bigger NTRU size */
    MAX_LENGTH_SZ       =   4 
};


enum Oid_Types {
    hashType = 0,
    sigType  = 1,
    keyType  = 2
};


enum Sig_Sum  {
    SHAwDSA   = 517,
    MD2wRSA   = 646,
    MD5wRSA   = 648,
    SHAwRSA   = 649,
    SHAwECDSA = 520
};

enum Hash_Sum  {
    MD2h  = 646,
    MD5h  = 649,
    SHAh  =  88
};

enum Key_Sum {
    DSAk   = 515,
    RSAk   = 645,
    NTRUk  = 364,
    ECDSAk = 518
};

enum Ecc_Sum {
    ECC_256R1 = 526,
    ECC_384R1 = 210,
    ECC_521R1 = 211,
    ECC_160R1 = 184,
    ECC_192R1 = 520,
    ECC_224R1 = 209
};


/* Certificate file Type */
enum CertType {
    CERT_TYPE       = 0, 
    PRIVATEKEY_TYPE,
    CA_TYPE
};


enum VerifyType {
    NO_VERIFY = 0,
    VERIFY    = 1
};


typedef struct DecodedCert {
    byte*   publicKey;
    word32  pubKeySize;
    int     pubKeyStored;
    word32  certBegin;               /* offset to start of cert          */
    word32  sigIndex;                /* offset to start of signature     */
    word32  sigLength;               /* length of signature              */
    word32  signatureOID;            /* sum of algorithm object id       */
    word32  keyOID;                  /* sum of key algo  object id       */
    byte    subjectHash[SHA_SIZE];   /* hash of all Names                */
    byte    issuerHash[SHA_SIZE];    /* hash of all Names                */
    byte*   signature;               /* not owned, points into raw cert  */
    char*   subjectCN;               /* CommonName                       */
    int     subjectCNLen;
    char    issuer[ASN_NAME_MAX];    /* full name including common name  */
    char    subject[ASN_NAME_MAX];   /* full name including common name  */
    int     verify;                  /* Default to yes, but could be off */
    byte*   source;                  /* byte buffer holder cert, NOT owner */
    word32  srcIdx;                  /* current offset into buffer       */
    void*   heap;                    /* for user memory overrides        */
#ifdef CYASSL_CERT_GEN
    /* easy access to sujbect info for other sign */
    char*   subjectSN;
    int     subjectSNLen;
    char*   subjectC;
    int     subjectCLen;
    char*   subjectL;
    int     subjectLLen;
    char*   subjectST;
    int     subjectSTLen;
    char*   subjectO;
    int     subjectOLen;
    char*   subjectOU;
    int     subjectOULen;
    char*   subjectEmail;
    int     subjectEmailLen;
#endif /* CYASSL_CERT_GEN */
} DecodedCert;


typedef struct Signer Signer;

/* CA Signers */
struct Signer {
    byte*   publicKey;
    word32  pubKeySize;
    word32  keyOID;                  /* key type */
    char*   name;                    /* common name */
    byte    hash[SHA_DIGEST_SIZE];   /* sha hash of names in certificate */
    Signer* next;
};


void InitDecodedCert(DecodedCert*, byte*, void*);
void FreeDecodedCert(DecodedCert*);
int  ParseCert(DecodedCert*, word32, int type, int verify, Signer* signer);
int  ParseCertRelative(DecodedCert*, word32, int type, int verify,
                       Signer* signer);

word32 EncodeSignature(byte* out, const byte* digest, word32 digSz,int hashOID);

Signer* MakeSigner(void*);
void    FreeSigners(Signer*, void*);


int RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey*, word32);
int RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey*, word32);
int ToTraditional(byte* buffer, word32 length);

#ifndef NO_DH
int DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32);
int DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g, word32 gSz);
#endif

#ifndef NO_DSA
int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey*, word32);
int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey*, word32);
#endif

#ifdef CYASSL_KEY_GEN
int RsaKeyToDer(RsaKey*, byte* output, word32 inLen);
#endif

#ifdef HAVE_ECC
    /* ASN sig helpers */
    int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s);
    int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen, mp_int* r, mp_int* s);
    /* private key helpers */
    int EccPrivateKeyDecode(const byte* input,word32* inOutIdx,ecc_key*,word32);
#endif

#if defined(CYASSL_KEY_GEN) || defined(CYASSL_CERT_GEN)
int DerToPem(const byte* der, word32 derSz, byte* output, word32 outputSz,
             int type);
#endif

#ifdef CYASSL_CERT_GEN

enum cert_enums {
    SERIAL_SIZE     =  8,
    NAME_SIZE       = 64,
    NAME_ENTRIES    =  8,
    JOINT_LEN       =  2,
    EMAIL_JOINT_LEN =  9,
    RSA_KEY         = 10,
    NTRU_KEY        = 11
};


typedef struct CertName {
    char country[NAME_SIZE];
    char state[NAME_SIZE];
    char locality[NAME_SIZE];
    char sur[NAME_SIZE];
    char org[NAME_SIZE];
    char unit[NAME_SIZE];
    char commonName[NAME_SIZE];
    char email[NAME_SIZE];  /* !!!! email has to be last !!!! */
} CertName;


/* for user to fill for certificate generation */
typedef struct Cert {
    int      version;                   /* x509 version  */
    byte     serial[SERIAL_SIZE];       /* serial number */
    int      sigType;                   /* signature algo type */
    CertName issuer;                    /* issuer info */
    int      daysValid;                 /* validity days */
    int      selfSigned;                /* self signed flag */
    CertName subject;                   /* subject info */
    /* internal use only */
    int      bodySz;                    /* pre sign total size */
    int      keyType;                   /* public key type of subject */
} Cert;


/* Initialize and Set Certficate defaults:
   version    = 3 (0x2)
   serial     = 0 (Will be randomly generated)
   sigType    = MD5_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
   keyType    = RSA_KEY (default)
*/
void InitCert(Cert*);
int  MakeCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
int  SignCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
int  MakeSelfCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*, RNG*);
int  SetIssuer(Cert*, const char*);
#ifdef HAVE_NTRU
int  MakeNtruCert(Cert*, byte* derBuffer, word32 derSz, const byte* ntruKey,
                  word16 keySz, RNG*);
#endif


#endif /* CYASSL_CERT_GEN */


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_ASN_H */

