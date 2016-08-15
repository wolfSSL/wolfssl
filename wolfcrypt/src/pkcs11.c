#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_PKCS11

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/pkcs11.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/asn.h>

static CK_ATTRIBUTE *wc_PKCS11_find_attributes(CK_ATTRIBUTE_TYPE type,
                                               CK_ATTRIBUTE *attr,
                                               CK_SIZE attrNbEnries)
{
    CK_SIZE i;

    if (attr == NULL_PTR)
        return NULL;

    for (i = 0; i < attrNbEnries; i++) {
        if (attr[i].type == type)
            return &attr[i];
    }

    return NULL;
}

static CK_RV wc_PKCS11_find_object(CK_SESSION_HANDLE sessionId,
									   CK_OBJECT_CLASS objClass,
									   CK_CHAR_PTR pObjLabel,
									   CK_OBJECT_HANDLE_PTR phObj)
{
	CK_RV rv = CKR_OK;

	CK_ATTRIBUTE objectTemplate[] = {
		{CKA_CLASS,         NULL,       0},
		{CKA_LABEL,         NULL,       0},
	};

	CK_SIZE templateSize = sizeof(objectTemplate) / sizeof(CK_ATTRIBUTE);

	CK_ULONG numObjectsToFind = 1;
	CK_ULONG numObjectsFound = 0;

    CK_ATTRIBUTE* pAttr = NULL;

    if (sessionId == CK_INVALID_HANDLE || pObjLabel == NULL_PTR ||
        phObj == NULL_PTR)
        return BAD_FUNC_ARG;

	/* Set the object class */
    pAttr = wc_PKCS11_find_attributes(CKA_CLASS, objectTemplate, templateSize);
    if (pAttr == NULL)
        return PKCS11_FIND_ATTR_E;

	pAttr->pValue = &objClass;
	pAttr->ulValueLen = sizeof(CK_OBJECT_CLASS);

	/* Set the label */
    pAttr = wc_PKCS11_find_attributes(CKA_LABEL, objectTemplate, templateSize);
    if (pAttr == NULL)
        return PKCS11_FIND_ATTR_E;

	pAttr->pValue = pObjLabel;
	pAttr->ulValueLen = strlen((char*)pObjLabel);

	/* Initialise the search operation */
	rv = C_FindObjectsInit(sessionId, objectTemplate, templateSize);
	if (rv != CKR_OK)
		return PKCS11_FINDOBJINIT_E;

	/* Search */
	rv = C_FindObjects(sessionId, phObj, numObjectsToFind, &numObjectsFound);
	if (rv != CKR_OK)
		return PKCS11_FINDOBJ_E;

	/* Terminate the search */
	rv = C_FindObjectsFinal(sessionId);
	if (rv != CKR_OK)
		return PKCS11_FINDOBJFINAL_E;

	/* Check to see if we found a matching object */
	if (!numObjectsFound)
		return PKCS11_FINDOBJ_NONE;

	return 0;
}


int wc_PKCS11_GetPublicKey(CK_SESSION_HANDLE sessionId, CK_BYTE_PTR pModulus,
                           CK_ULONG pModulusSz, CK_OBJECT_HANDLE_PTR phKpub)
{
    CK_RV rv = CKR_OK;
    CK_OBJECT_CLASS cko = CKO_PUBLIC_KEY;

    CK_ATTRIBUTE kPubTemplate[] = {
        {CKA_CLASS,    &cko, sizeof(cko)},
        {CKA_MODULUS,  NULL,           0}
    };

    CK_SIZE templateSize = sizeof(kPubTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ULONG numKpubToFind = 1;
    CK_ULONG numKpubFound = 0;

    CK_ATTRIBUTE* pAttr = NULL;

    if (sessionId == CK_INVALID_HANDLE || pModulus == NULL_PTR ||
        phKpub == NULL_PTR)
        return BAD_FUNC_ARG;

    /* Set the modulus */
    pAttr = wc_PKCS11_find_attributes(CKA_MODULUS, kPubTemplate, templateSize);
    if (pAttr == NULL)
        return PKCS11_FIND_ATTR_E;

    pAttr->pValue = pModulus;
    pAttr->ulValueLen = pModulusSz;

    /* Initialise the search operation */
    rv = C_FindObjectsInit(sessionId, kPubTemplate, templateSize);
    if (rv != CKR_OK)
        return PKCS11_FINDOBJINIT_E;

    /* Search */
    rv = C_FindObjects(sessionId, phKpub, numKpubToFind, &numKpubFound);
    if (rv != CKR_OK)
        return PKCS11_FINDOBJ_E;

    /* Terminate the search */
    rv = C_FindObjectsFinal(sessionId);
    if (rv != CKR_OK)
        return PKCS11_FINDOBJFINAL_E;
    
    /* Check to see if we found a matching object */
    if (!numKpubFound)
        return PKCS11_FINDOBJ_NONE;
    
    return 0;
}


static CK_RV wc_PKCS11_delete_rsakey_handle(CK_SESSION_HANDLE sessionId,
												CK_OBJECT_HANDLE hPublicKey,
												CK_OBJECT_HANDLE hPrivateKey)
{
	CK_RV rv;

	if (sessionId == CK_INVALID_HANDLE || hPublicKey == CK_INVALID_HANDLE ||
		hPrivateKey == CK_INVALID_HANDLE)
		return BAD_FUNC_ARG;

	/* delete the private key */
	rv = C_DestroyObject(sessionId, hPublicKey);
	if (rv != CKR_OK)
		return PKCS11_DELETEOBJ_E;

	/* delete public key */
	rv = C_DestroyObject(sessionId, hPrivateKey);
	if (rv != CKR_OK)
		return PKCS11_DELETEOBJ_E;

	return 0;
}


/* Init PKCS11 library
 */
int wc_PKCS11_Init(void)
{
	CK_RV rv;

    WOLFSSL_ENTER("wc_PKCS11_Init");

	rv = C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return PKCS11_INIT_E;

	return 0;
}


/* Finalize PKCS11 library
 *
 * sessionId : previously opened session.
 */
void wc_PKCS11_Cleanup(void)
{
    WOLFSSL_ENTER("wc_PKCS11_Cleanup");

    C_Finalize(NULL);
}


/* Open a session and login
 *
 * slotId : to slot to connect in
 * pin : pin code to login in the slot
 * sessionId : Handle to the opened session (updated if no error).
 */
int wc_PKCS11_OpenSession(CK_SLOT_ID slotId, CK_CHAR_PTR pin,
                          CK_SESSION_HANDLE_PTR sessionId)
{
    CK_RV rv;

    WOLFSSL_ENTER("wc_PKCS11_OpenSession");

    if (sessionId == NULL_PTR || pin == NULL_PTR)
        return BAD_FUNC_ARG;

    rv = C_OpenSession(slotId, CKF_RW_SESSION|CKF_SERIAL_SESSION,
                       NULL, NULL, sessionId);
    if (rv != CKR_OK) {
        C_Finalize(NULL);
        return PKCS11_OPENSESSION_E;
    }

    rv = C_Login(*sessionId, CKU_USER, pin, (CK_SIZE)strlen((const char *)pin));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        C_CloseSession(*sessionId);
        C_Finalize(NULL);
        return PKCS11_LOGIN_E;
    }
    
    return 0;
}


/* Logout and Close an opened session
 */
void wc_PKCS11_CloseSession(CK_SESSION_HANDLE sessionId)
{
    WOLFSSL_ENTER("wc_PKCS11_CloseSession");

    if (sessionId != CK_INVALID_HANDLE)
        C_Logout(sessionId);

    if (sessionId != CK_INVALID_HANDLE)
        C_CloseSession(sessionId);
}


/* Search the key and return an handle on it
 */
int wc_PKCS11_KeyLoad(CK_SESSION_HANDLE sessionId,
                       CK_CHAR_PTR keyName, int keyType,
                       CK_OBJECT_HANDLE *hKey)
{
    CK_RV rv;
    CK_OBJECT_CLASS cko;

    WOLFSSL_ENTER("wc_PKCS11_KeyLoad");

    if (sessionId == CK_INVALID_HANDLE || keyName == NULL_PTR ||
        (keyType != RSA_PRIVATE && keyType != RSA_PUBLIC) || hKey == NULL_PTR)
        return BAD_FUNC_ARG;

    /* search private key */
    switch (keyType) {
        case RSA_PUBLIC:
            cko = CKO_PUBLIC_KEY;
            break;

        case RSA_PRIVATE:
            cko = CKO_PRIVATE_KEY;
            break;

        default:
            return PKCS11_KEYTYPE_E;
            break;
    }

    rv = wc_PKCS11_find_object(sessionId, cko, keyName, hKey);
    if (rv != CKR_OK)
        return PKCS11_FIND_KEY_E;

    return 0;
}


int wc_PKCS11_ReadPublicKey(CK_SESSION_HANDLE sessionId, CK_OBJECT_HANDLE hKey,
                            byte **modulus, word32 *modulusSz,
                            byte **exponent, word32 *exponentSz)
{
	CK_RV rv;

    CK_ATTRIBUTE template[] = {
        {CKA_MODULUS,		  NULL, 0},
        {CKA_PUBLIC_EXPONENT, NULL, 0},
    };

    WOLFSSL_ENTER("wc_PKCS11_ReadPublicKey");

    if (sessionId == CK_INVALID_HANDLE || hKey == CK_INVALID_HANDLE ||
        modulus == NULL || modulusSz == NULL ||
        exponent == NULL || exponentSz == NULL)
        return BAD_FUNC_ARG;

	rv = C_GetAttributeValue(sessionId, hKey, template,
                             sizeof(template)/sizeof(CK_ATTRIBUTE));
	if (rv != CKR_OK)
		return PKCS11_GET_VALUE_E;

    *modulusSz  = template[0].ulValueLen;
    *exponentSz = template[1].ulValueLen;

    *modulus = XMALLOC(*modulusSz, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (*modulus == NULL)
        return MEMORY_E;

    *exponent = XMALLOC(*exponentSz, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (*exponent == NULL) {
        XFREE(modulus, 0, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

	template[0].pValue = *modulus;
	template[1].pValue = *exponent;

	rv = C_GetAttributeValue(sessionId, hKey, template,
                             sizeof(template)/sizeof(CK_ATTRIBUTE));
    if (rv != CKR_OK) {
        XFREE(*modulus, 0, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(*exponent, 0, DYNAMIC_TYPE_TMP_BUFFER);
        *modulusSz  = 0;
        *exponentSz = 0;
        return PKCS11_GET_VALUE_E;
    }

	return 0;
}

int wc_PKCS11_PrivateKeyEncodeDer(byte* key, word32 *keySz,
                                  CK_OBJECT_HANDLE hPrvkey,
                                  CK_OBJECT_HANDLE hPubkey)
{
    word16 keyHdleSz = sizeof(CK_OBJECT_HANDLE);
    word16 i, idx = 0;

    WOLFSSL_ENTER("wc_PKCS11_PrivateKeyEncodeDer");

    if (key == NULL || keySz == NULL || (*keySz) < 2 * sizeof(CK_OBJECT_HANDLE))
        return BAD_FUNC_ARG;

    /* encode private key handle */
    for (i = 0; i < keyHdleSz; i++)
        key[idx++] = (hPrvkey >> ((keyHdleSz-1-i)*8)) & 0xff;

    /* encode public key handle */
    for (i = 0; i < keyHdleSz; i++)
        key[idx++] = (hPubkey >> ((keyHdleSz-1-i)*8)) & 0xff;

    *keySz = idx;

    return 0;
}


/* Generate an RSA Key Pair
 */
int wc_PKCS11_GenerateRsa(CK_SESSION_HANDLE sessionId, CK_SIZE keySize,
                          CK_CHAR_PTR keyName)
{
	CK_RV rv;

	CK_OBJECT_HANDLE phPublicKey;
	CK_OBJECT_HANDLE phPrivateKey;
    CK_BBOOL True = TRUE;
    CK_BBOOL False = FALSE;

    WOLFSSL_ENTER("wc_PKCS11_GenerateRsa");

	/* RSA keypair generation */
	CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};

	/* RSA public exponent value */
	CK_BYTE  fermat4[] = { 1, 0, 1 };

	/* Attribute template for the public key */
	CK_ATTRIBUTE attribute_pubkey[] =
	{
		{CKA_LABEL,             NULL,   0},
        {CKA_TOKEN,             &True,   sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &False,  sizeof(CK_BBOOL)},
		{CKA_ENCRYPT,           &True,   sizeof(CK_BBOOL)},
		{CKA_VERIFY,            &True,   sizeof(CK_BBOOL)},
		{CKA_WRAP,              &True,   sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,        &True,   sizeof(CK_BBOOL)},
		{CKA_DERIVE,            &True,   sizeof(CK_BBOOL)},
		{CKA_MODULUS_BITS,      &keySize,  sizeof(CK_ULONG)},
		{CKA_PUBLIC_EXPONENT,   fermat4,   sizeof(fermat4)},
	};

	/* Attribute template for the private key */
	CK_ATTRIBUTE attribute_prvkey[] =
	{
        {CKA_LABEL,             NULL,   0},
		{CKA_TOKEN,             &True,   sizeof(CK_BBOOL)},
		{CKA_PRIVATE,           &True,  sizeof(CK_BBOOL)},
		{CKA_SENSITIVE,         &True,   sizeof(CK_BBOOL)},
		{CKA_DECRYPT,           &True,   sizeof(CK_BBOOL)},
		{CKA_SIGN,              &True,   sizeof(CK_BBOOL)},
		{CKA_UNWRAP,            &True,   sizeof(CK_BBOOL)},
		{CKA_MODIFIABLE,        &True,   sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE,       &True,   sizeof(CK_BBOOL)},
		{CKA_DERIVE,            &True,   sizeof(CK_BBOOL)},
#if 0
        /* could be required for some HSM */
        {CKA_IMPORT,            &False,  sizeof(CK_BBOOL)},
        {CKA_EXPORTABLE,        &True,   sizeof(CK_BBOOL)},
        {CKA_SIGN_LOCAL_CERT,   &False,  sizeof(CK_BBOOL)},
#endif
	};

	/* check arguments */
	if (sessionId == CK_INVALID_HANDLE || keyName == NULL_PTR)
		return BAD_FUNC_ARG;

    /* set label */
    attribute_pubkey[0].pValue = keyName;
    attribute_pubkey[0].ulValueLen = strlen((const char *)keyName);
    attribute_prvkey[0].pValue = keyName;
    attribute_prvkey[0].ulValueLen = attribute_pubkey[0].ulValueLen;

	/* Generate the key pair */
	rv = C_GenerateKeyPair(sessionId,
						   &mech,
						   attribute_pubkey,
						   sizeof(attribute_pubkey)/sizeof(CK_ATTRIBUTE),
						   attribute_prvkey,
						   sizeof(attribute_prvkey)/sizeof(CK_ATTRIBUTE),
						   &phPublicKey, &phPrivateKey);
	if (rv != CKR_OK)
		return PKCS11_GENKEY_E;

	return 0;
}


int wc_PKCS11_DeleteRsa(CK_SESSION_HANDLE sessionId, CK_CHAR_PTR keyName)
{
	int	ret;

	CK_OBJECT_HANDLE hPubKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrvKey = CK_INVALID_HANDLE;

    WOLFSSL_ENTER("wc_PKCS11_DeleteRsa");

	/* check arguments */
	if (sessionId == CK_INVALID_HANDLE || keyName == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	/* search private key */
	ret = wc_PKCS11_find_object(sessionId, CKO_PRIVATE_KEY,
                                (CK_CHAR_PTR)keyName, &hPrvKey);
	if (ret != 0)
		return ret;

	/* search public key */
	ret = wc_PKCS11_find_object(sessionId, CKO_PUBLIC_KEY,
                                (CK_CHAR_PTR)keyName, &hPubKey);
	if (ret != 0)
		return ret;

	/* delete key pair */
	ret = wc_PKCS11_delete_rsakey_handle(sessionId, hPubKey, hPrvKey);
	if (ret != 0)
		return ret;

    return 0;
}

int wc_PKCS11_RsaSign(CK_SESSION_HANDLE sessionId, CK_OBJECT_HANDLE hPrvKey,
                       CK_BYTE_PTR digest, CK_ULONG digestLen,
                       CK_BYTE_PTR sign, CK_ULONG_PTR signLen)
{
    CK_RV	rv;
    /* set RSA PKCS mechanism */
    CK_MECHANISM signMech = {CKM_RSA_PKCS, NULL, 0};

    WOLFSSL_ENTER("wc_PKCS11_RsaSign");

	/* check arguments */
	if (sessionId == CK_INVALID_HANDLE || hPrvKey == CK_INVALID_HANDLE ||
		digest == NULL_PTR || sign == NULL_PTR || signLen == NULL_PTR)
		return BAD_FUNC_ARG;

     /* Initialise the sign operation */
    rv = C_SignInit(sessionId, &signMech, hPrvKey);
	if (rv != CKR_OK)
		return PKCS11_SIGNINIT_E;

    /* Do the signature */
    rv = C_Sign(sessionId, digest, digestLen, sign, signLen);
	if (rv != CKR_OK) {
        *signLen = 0;
		return PKCS11_SIGN_E;
    }

    return 0;
}

int wc_PKCS11_RsaVerify(CK_SESSION_HANDLE sessionId, CK_OBJECT_HANDLE hPubKey,
                         CK_BYTE_PTR digest, CK_ULONG digestLen,
                         CK_BYTE_PTR sign, CK_ULONG signLen)
{
    CK_RV	rv;
    /* set RSA PKCS mechanism */
    CK_MECHANISM verifyMech = {CKM_RSA_PKCS, NULL, 0};

    WOLFSSL_ENTER("wc_PKCS11_RsaVerify");

    /* check arguments */
    if (sessionId == CK_INVALID_HANDLE || hPubKey == CK_INVALID_HANDLE ||
        digest == NULL_PTR || sign == NULL_PTR)
        return BAD_FUNC_ARG;

    /* Initialise the verify operation */
    rv = C_VerifyInit(sessionId, &verifyMech, hPubKey);
    if (rv != CKR_OK)
        return PKCS11_VERIFYINIT_E;

    /* Verify the signature */
    rv = C_Verify(sessionId, digest, digestLen, sign, signLen);
    if (rv != CKR_OK)
        return PKCS11_VERIFY_E;

    return 0;
}

int wc_PKCS11_RsaEncrypt(CK_SESSION_HANDLE sessionId, CK_OBJECT_HANDLE hPubKey,
                          CK_BYTE_PTR data, CK_ULONG dataLen,
                          CK_BYTE_PTR encData, CK_ULONG_PTR encDataLen)
{
    CK_RV	rv;
    /* set RSA mechanism */
    CK_MECHANISM encMech = {CKM_RSA_PKCS, NULL, 0};

    WOLFSSL_ENTER("wc_PKCS11_RsaEncrypt");

    /* check arguments */
    if (sessionId == CK_INVALID_HANDLE || hPubKey == CK_INVALID_HANDLE ||
        data == NULL_PTR || encData == NULL_PTR || encDataLen == NULL_PTR)
        return BAD_FUNC_ARG;

    /* Initialise the encrypt operation */
    rv = C_EncryptInit(sessionId, &encMech, hPubKey);
    if (rv != CKR_OK)
        return PKCS11_ENCRYPTINIT_E;

    /* Do the encryption */
    rv = C_Encrypt(sessionId, data, dataLen, encData, encDataLen);
    if (rv != CKR_OK) {
        *encDataLen = 0;
        return PKCS11_ENCRYPT_E;
    }
    
    return 0;
}

int wc_PKCS11_RsaDecrypt(CK_SESSION_HANDLE sessionId, CK_OBJECT_HANDLE hPrvKey,
                          CK_BYTE_PTR encData, CK_ULONG encDataLen,
                          CK_BYTE_PTR data, CK_ULONG_PTR dataLen)
{
    CK_RV	rv;
    /* set RSA mechanism */
    CK_MECHANISM decMech = {CKM_RSA_PKCS, NULL, 0};

    WOLFSSL_ENTER("wc_PKCS11_RsaDecrypt");

    /* check arguments */
    if (sessionId == CK_INVALID_HANDLE || hPrvKey == CK_INVALID_HANDLE ||
        encData == NULL_PTR || data == NULL_PTR || dataLen == NULL_PTR)
        return BAD_FUNC_ARG;

    /* Initialise the decrypt operation */
    rv = C_DecryptInit(sessionId, &decMech, hPrvKey);
    if (rv != CKR_OK)
        return PKCS11_DECRYPTINIT_E;

    /* Do the decryption */
    rv = C_Decrypt(sessionId, encData, encDataLen, data, dataLen);
    if (rv != CKR_OK) {
        *dataLen = 0;
        return PKCS11_DECRYPT_E;
    }

    return 0;
}

int wc_PKCS11_RsaEncryptRaw(CK_SESSION_HANDLE sessionId,
                            CK_OBJECT_HANDLE hPubKey,
                            CK_BYTE_PTR data, CK_ULONG dataLen,
                            CK_BYTE_PTR encData, CK_ULONG_PTR encDataLen)
{
    CK_RV	rv;
    /* set RSA mechanism */
    CK_MECHANISM encMech = {CKM_RSA_X_509, NULL, 0};

    WOLFSSL_ENTER("wc_PKCS11_RsaEncryptRaw");

    /* check arguments */
    if (sessionId == CK_INVALID_HANDLE || hPubKey == CK_INVALID_HANDLE ||
        data == NULL_PTR || encData == NULL_PTR || encDataLen == NULL_PTR)
        return BAD_FUNC_ARG;

    /* Initialise the encrypt operation */
    rv = C_EncryptInit(sessionId, &encMech, hPubKey);
    if (rv != CKR_OK)
        return PKCS11_ENCRYPTINIT_E;

    /* Do the encryption */
    rv = C_Encrypt(sessionId, data, dataLen, encData, encDataLen);
    if (rv != CKR_OK) {
        *encDataLen = 0;
        return PKCS11_ENCRYPT_E;
    }

    return 0;
}

int wc_PKCS11_RsaDecryptRaw(CK_SESSION_HANDLE sessionId,
                            CK_OBJECT_HANDLE hPrvKey,
                            CK_BYTE_PTR encData, CK_ULONG encDataLen,
                            CK_BYTE_PTR data, CK_ULONG_PTR dataLen)
{
    CK_RV	rv;
    /* set RSA mechanism */
    CK_MECHANISM decMech = {CKM_RSA_X_509, NULL, 0};

    WOLFSSL_ENTER("wc_PKCS11_RsaDecryptRaw");

    /* check arguments */
    if (sessionId == CK_INVALID_HANDLE || hPrvKey == CK_INVALID_HANDLE ||
        encData == NULL_PTR || data == NULL_PTR || dataLen == NULL_PTR)
        return BAD_FUNC_ARG;

    /* Initialise the decrypt operation */
    rv = C_DecryptInit(sessionId, &decMech, hPrvKey);
    if (rv != CKR_OK)
        return PKCS11_DECRYPTINIT_E;


    /* Do the decryption */
    rv = C_Decrypt(sessionId, encData, encDataLen, data, dataLen);
    if (rv != CKR_OK) {
        *dataLen = 0;
        return PKCS11_DECRYPT_E;
    }

    return 0;
}

int wc_PKCS11_RsaEncryptOAEP(CK_SESSION_HANDLE sessionId,
                             CK_OBJECT_HANDLE hPubKey,
                             CK_BYTE_PTR data, CK_ULONG dataLen,
                             CK_BYTE_PTR encData, CK_ULONG_PTR encDataLen,
                             CK_BYTE_PTR label, CK_ULONG labelLen,
                             int hash_type, int mgf)
{
    CK_RV	rv;
    /* set RSA mechanism */
    CK_MECHANISM encMech = {CKM_RSA_PKCS_OAEP, NULL, 0};
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;

    WOLFSSL_ENTER("wc_PKCS11_RsaEncryptOAEP");

    /* check arguments */
    /* SoftHSM case : label must be NULL and labelLen must be 0 */
    if (sessionId == CK_INVALID_HANDLE || hPubKey == CK_INVALID_HANDLE ||
        data == NULL_PTR || encData == NULL_PTR ||  encDataLen == NULL_PTR)
        return BAD_FUNC_ARG;

    oaep_params.source = CKZ_DATA_SPECIFIED;
    oaep_params.pSourceData = label;
    oaep_params.ulSourceDataLen = labelLen;

    switch(hash_type)
    {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            oaep_params.hashAlg = CKM_SHA_1;
            break;
#endif
            /* hash below are not available with SoftHSM for OAEP */
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            oaep_params.hashAlg = CKM_SHA256;
            break;
#endif
#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_SHA384)
        case WC_HASH_TYPE_SHA384:
            oaep_params.hashAlg = CKM_SHA384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            oaep_params.hashAlg = CKM_SHA512;
            break;
#endif
        default:
            return PKCS11_HASHTYPE_E;
            break;
    }

    switch(mgf) {
#ifndef NO_SHA
        case WC_MGF1SHA1:
            oaep_params.mgf = CKG_MGF1_SHA1;
            break;
#endif
            /* MGF below are not available with SoftHSM for OAEP */
#ifndef NO_SHA256
        case WC_MGF1SHA256:
            oaep_params.mgf = CKG_MGF1_SHA256;
            break;
#endif
#ifdef WOLFSSL_SHA512
#ifdef WOLFSSL_SHA384
        case WC_MGF1SHA384:
            oaep_params.mgf = CKG_MGF1_SHA384;
            break;
#endif
        case WC_MGF1SHA512:
            oaep_params.mgf = CKG_MGF1_SHA512;
            break;
#endif
        default:
            return PKCS11_MGF_E;
            break;
    }

    /* Set OAEP parameters */
    encMech.pParameter = &oaep_params;
    encMech.ulParameterLen = sizeof(oaep_params);

    /* Initialise the encrypt operation */
    rv = C_EncryptInit(sessionId, &encMech, hPubKey);
    if (rv != CKR_OK)
        return PKCS11_ENCRYPTINIT_E;

    /* Do the encryption */
    rv = C_Encrypt(sessionId, data, dataLen, encData, encDataLen);
    if (rv != CKR_OK) {
        *encDataLen = 0;
        return PKCS11_ENCRYPT_E;
    }

    return 0;
}

int wc_PKCS11_RsaDecryptOAEP(CK_SESSION_HANDLE sessionId,
                             CK_OBJECT_HANDLE hPrvKey,
                             CK_BYTE_PTR encData, CK_ULONG encDataLen,
                             CK_BYTE_PTR data, CK_ULONG_PTR dataLen,
                             CK_BYTE_PTR label, CK_ULONG labelLen,
                             int hash_type, int mgf)
{
    CK_RV	rv;
    /* set RSA mechanism */
    CK_MECHANISM decMech = {CKM_RSA_PKCS_OAEP, NULL, 0};
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;

    WOLFSSL_ENTER("wc_PKCS11_RsaDecryptOAEP");

    /* check arguments */
    if (sessionId == CK_INVALID_HANDLE || hPrvKey == CK_INVALID_HANDLE ||
        encData == NULL_PTR || data == NULL_PTR || dataLen == NULL_PTR)
        return BAD_FUNC_ARG;

    /* SoftHSM don't suppport label */
    if (label != NULL_PTR || labelLen != 0)
        return PKCS11_OAEPLABEL_E;

    oaep_params.source = CKZ_DATA_SPECIFIED;
    oaep_params.pSourceData = label;
    oaep_params.ulSourceDataLen = labelLen;

    switch(hash_type)
    {
#ifndef NO_SHA
        case WC_HASH_TYPE_SHA:
            oaep_params.hashAlg = CKM_SHA_1;
            break;
#endif
        /* hash below are not available with SoftHSM for OAEP */
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            oaep_params.hashAlg = CKM_SHA256;
            break;
#endif
#if defined(WOLFSSL_SHA512) && defined(WOLFSSL_SHA384)
        case WC_HASH_TYPE_SHA384:
            oaep_params.hashAlg = CKM_SHA384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            oaep_params.hashAlg = CKM_SHA512;
            break;
#endif
        default:
            return PKCS11_HASHTYPE_E;
            break;
    }

    switch(mgf) {
#ifndef NO_SHA
        case WC_MGF1SHA1:
            oaep_params.mgf = CKG_MGF1_SHA1;
            break;
#endif
        /* MGF below are not available with SoftHSM for OAEP */
#ifndef NO_SHA256
        case WC_MGF1SHA256:
            oaep_params.mgf = CKG_MGF1_SHA256;
            break;
#endif
#ifdef WOLFSSL_SHA512
#ifdef WOLFSSL_SHA384
        case WC_MGF1SHA384:
            oaep_params.mgf = CKG_MGF1_SHA384;
            break;
#endif
        case WC_MGF1SHA512:
            oaep_params.mgf = CKG_MGF1_SHA512;
            break;
#endif
        default:
            return PKCS11_MGF_E;
            break;
    }

    /* Set OAEP parameters */
    decMech.pParameter = &oaep_params;
    decMech.ulParameterLen = sizeof(oaep_params);

    /* Initialise the decrypt operation */
    rv = C_DecryptInit(sessionId, &decMech, hPrvKey);
    if (rv != CKR_OK)
        return PKCS11_DECRYPTINIT_E;

    /* Do the decryption */
    rv = C_Decrypt(sessionId, encData, encDataLen, data, dataLen);
    if (rv != CKR_OK) {
        *dataLen = 0;
        return PKCS11_DECRYPT_E;
    }

    return 0;
}

#else  /* HAVE_PKCS11 */

#ifdef _MSC_VER
/* 4206 warning for blank file */
#pragma warning(disable: 4206)
#endif

#endif /* HAVE_PKCS11 */
