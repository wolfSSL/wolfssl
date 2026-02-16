/* pk_ec.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/internal.h>
#ifndef WC_NO_RNG
    #include <wolfssl/wolfcrypt/random.h>
#endif

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
    #ifdef HAVE_SELFTEST
        /* point compression types. */
        #define ECC_POINT_COMP_EVEN 0x02
        #define ECC_POINT_COMP_ODD  0x03
        #define ECC_POINT_UNCOMP    0x04
    #endif
#endif
#ifndef WOLFSSL_HAVE_ECC_KEY_GET_PRIV
    /* FIPS build has replaced ecc.h. */
    #define wc_ecc_key_get_priv(key) (&((key)->k))
    #define WOLFSSL_HAVE_ECC_KEY_GET_PRIV
#endif

#if !defined(WOLFSSL_PK_EC_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning pk_ec.c does not need to be compiled separately from ssl.c
    #endif
#else

/*******************************************************************************
 * START OF EC API
 ******************************************************************************/

#ifdef HAVE_ECC

#if defined(OPENSSL_EXTRA)

/* Start EC_curve */

/* Get the NIST name for the numeric ID.
 *
 * @param [in] nid  Numeric ID of an EC curve.
 * @return  String representing NIST name of EC curve on success.
 * @return  NULL on error.
 */
const char* wolfSSL_EC_curve_nid2nist(int nid)
{
    const char* name = NULL;
    const WOLF_EC_NIST_NAME* nist_name;

    /* Attempt to find the curve info matching the NID passed in. */
    for (nist_name = kNistCurves; nist_name->name != NULL; nist_name++) {
        if (nist_name->nid == nid) {
            /* NID found - return name. */
            name = nist_name->name;
            break;
        }
    }

    return name;
}

/* Get the numeric ID for the NIST name.
 *
 * @param [in] name  NIST name of EC curve.
 * @return  NID matching NIST name on success.
 * @return  0 on error.
 */
int wolfSSL_EC_curve_nist2nid(const char* name)
{
    int nid = 0;
    const WOLF_EC_NIST_NAME* nist_name;

    /* Attempt to find the curve info matching the NIST name passed in. */
    for (nist_name = kNistCurves; nist_name->name != NULL; nist_name++) {
        if (XSTRCMP(nist_name->name, name) == 0) {
            /* Name found - return NID. */
            nid = nist_name->nid;
            break;
        }
    }

    return nid;
}

#endif /* OPENSSL_EXTRA */

/* End EC_curve */

/* Start EC_METHOD */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Get the EC method of the EC group object.
 *
 * wolfSSL doesn't use method tables. Implementation used is dependent upon
 * the NID.
 *
 * @param [in] group  EC group object.
 * @return  EC method.
 */
const WOLFSSL_EC_METHOD* wolfSSL_EC_GROUP_method_of(
    const WOLFSSL_EC_GROUP *group)
{
    /* No method table used so just return the same object. */
    return group;
}

/* Get field type for method.
 *
 * Only prime fields are supported.
 *
 * @param [in] meth  EC method.
 * @return  X9.63 prime field NID on success.
 * @return  0 on error.
 */
int wolfSSL_EC_METHOD_get_field_type(const WOLFSSL_EC_METHOD *meth)
{
    int nid = 0;

    if (meth != NULL) {
        /* Only field type supported by code base. */
        nid = WC_NID_X9_62_prime_field;
    }

    return nid;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

/* End EC_METHOD */

/* Start EC_GROUP */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Converts ECC curve enum values in ecc_curve_id to the associated OpenSSL NID
 * value.
 *
 * @param [in] n  ECC curve id.
 * @return  ECC curve NID (OpenSSL compatible value).
 */
int EccEnumToNID(int n)
{
    WOLFSSL_ENTER("EccEnumToNID");

    switch(n) {
        case ECC_SECP192R1:
            return WC_NID_X9_62_prime192v1;
        case ECC_PRIME192V2:
            return WC_NID_X9_62_prime192v2;
        case ECC_PRIME192V3:
            return WC_NID_X9_62_prime192v3;
        case ECC_PRIME239V1:
            return WC_NID_X9_62_prime239v1;
        case ECC_PRIME239V2:
            return WC_NID_X9_62_prime239v2;
        case ECC_PRIME239V3:
            return WC_NID_X9_62_prime239v3;
        case ECC_SECP256R1:
            return WC_NID_X9_62_prime256v1;
        case ECC_SECP112R1:
            return WC_NID_secp112r1;
        case ECC_SECP112R2:
            return WC_NID_secp112r2;
        case ECC_SECP128R1:
            return WC_NID_secp128r1;
        case ECC_SECP128R2:
            return WC_NID_secp128r2;
        case ECC_SECP160R1:
            return WC_NID_secp160r1;
        case ECC_SECP160R2:
            return WC_NID_secp160r2;
        case ECC_SECP224R1:
            return WC_NID_secp224r1;
        case ECC_SECP384R1:
            return WC_NID_secp384r1;
        case ECC_SECP521R1:
            return WC_NID_secp521r1;
        case ECC_SECP160K1:
            return WC_NID_secp160k1;
        case ECC_SECP192K1:
            return WC_NID_secp192k1;
        case ECC_SECP224K1:
            return WC_NID_secp224k1;
        case ECC_SECP256K1:
            return WC_NID_secp256k1;
        case ECC_BRAINPOOLP160R1:
            return WC_NID_brainpoolP160r1;
        case ECC_BRAINPOOLP192R1:
            return WC_NID_brainpoolP192r1;
        case ECC_BRAINPOOLP224R1:
            return WC_NID_brainpoolP224r1;
        case ECC_BRAINPOOLP256R1:
            return WC_NID_brainpoolP256r1;
        case ECC_BRAINPOOLP320R1:
            return WC_NID_brainpoolP320r1;
        case ECC_BRAINPOOLP384R1:
            return WC_NID_brainpoolP384r1;
        case ECC_BRAINPOOLP512R1:
            return WC_NID_brainpoolP512r1;
    #ifdef WOLFSSL_SM2
        case ECC_SM2P256V1:
            return WC_NID_sm2;
    #endif
        default:
            WOLFSSL_MSG("NID not found");
            return WOLFSSL_FATAL_ERROR;
    }
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Converts OpenSSL NID of EC curve to the enum value in ecc_curve_id
 *
 * Used by ecc_sets[].
 *
 * @param [in] n  OpenSSL NID of EC curve.
 * @return  wolfCrypt EC curve id.
 * @return  -1 on error.
 */
int NIDToEccEnum(int nid)
{
    int id;

    WOLFSSL_ENTER("NIDToEccEnum");

    switch (nid) {
        case WC_NID_X9_62_prime192v1:
            id = ECC_SECP192R1;
            break;
        case WC_NID_X9_62_prime192v2:
            id = ECC_PRIME192V2;
            break;
        case WC_NID_X9_62_prime192v3:
            id = ECC_PRIME192V3;
            break;
        case WC_NID_X9_62_prime239v1:
            id = ECC_PRIME239V1;
            break;
        case WC_NID_X9_62_prime239v2:
            id = ECC_PRIME239V2;
            break;
        case WC_NID_X9_62_prime239v3:
            id = ECC_PRIME239V3;
            break;
        case WC_NID_X9_62_prime256v1:
            id = ECC_SECP256R1;
            break;
        case WC_NID_secp112r1:
            id = ECC_SECP112R1;
            break;
        case WC_NID_secp112r2:
            id = ECC_SECP112R2;
            break;
        case WC_NID_secp128r1:
            id = ECC_SECP128R1;
            break;
        case WC_NID_secp128r2:
            id = ECC_SECP128R2;
            break;
        case WC_NID_secp160r1:
            id = ECC_SECP160R1;
            break;
        case WC_NID_secp160r2:
            id = ECC_SECP160R2;
            break;
        case WC_NID_secp224r1:
            id = ECC_SECP224R1;
            break;
        case WC_NID_secp384r1:
            id = ECC_SECP384R1;
            break;
        case WC_NID_secp521r1:
            id = ECC_SECP521R1;
            break;
        case WC_NID_secp160k1:
            id = ECC_SECP160K1;
            break;
        case WC_NID_secp192k1:
            id = ECC_SECP192K1;
            break;
        case WC_NID_secp224k1:
            id = ECC_SECP224K1;
            break;
        case WC_NID_secp256k1:
            id = ECC_SECP256K1;
            break;
        case WC_NID_brainpoolP160r1:
            id = ECC_BRAINPOOLP160R1;
            break;
        case WC_NID_brainpoolP192r1:
            id = ECC_BRAINPOOLP192R1;
            break;
        case WC_NID_brainpoolP224r1:
            id = ECC_BRAINPOOLP224R1;
            break;
        case WC_NID_brainpoolP256r1:
            id = ECC_BRAINPOOLP256R1;
            break;
        case WC_NID_brainpoolP320r1:
            id = ECC_BRAINPOOLP320R1;
            break;
        case WC_NID_brainpoolP384r1:
            id = ECC_BRAINPOOLP384R1;
            break;
        case WC_NID_brainpoolP512r1:
            id = ECC_BRAINPOOLP512R1;
            break;
        default:
            WOLFSSL_MSG("NID not found");
            /* -1 on error. */
            id = WOLFSSL_FATAL_ERROR;
    }

    return id;
}

/* Set the fields of the EC group based on numeric ID.
 *
 * @param [in, out] group  EC group.
 * @param [in]      nid    Numeric ID of an EC curve.
 */
static void ec_group_set_nid(WOLFSSL_EC_GROUP* group, int nid)
{
    int eccEnum;
    int realNid;

    /* Convert ecc_curve_id enum to NID. */
    if ((realNid = EccEnumToNID(nid)) != -1) {
        /* ecc_curve_id enum passed in - have real NID value set. */
        eccEnum = nid;
    }
    else {
        /* NID passed in is OpenSSL type. */
        realNid = nid;
        /* Convert NID to ecc_curve_id enum. */
        eccEnum = NIDToEccEnum(nid);
    }

    /* Set the numeric ID of the curve */
    group->curve_nid = realNid;
    /* Initialize index to -1 (i.e. wolfCrypt doesn't support curve). */
    group->curve_idx = -1;

    /* Find index and OID sum for curve if wolfCrypt supports it. */
    if (eccEnum != -1) {
        int i;

        /* Find id and set the internal curve idx and OID sum. */
        for (i = 0; ecc_sets[i].size != 0; i++) {
            if (ecc_sets[i].id == eccEnum) {
                /* Found id in wolfCrypt supported EC curves. */
                group->curve_idx = i;
                group->curve_oid = (int)ecc_sets[i].oidSum;
                break;
            }
        }
    }
}

/* Create a new EC group with the numeric ID for an EC curve.
 *
 * @param [in] nid  Numeric ID of an EC curve.
 * @return  New, allocated EC group on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_GROUP* wolfSSL_EC_GROUP_new_by_curve_name(int nid)
{
    int err = 0;
    WOLFSSL_EC_GROUP* group;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_new_by_curve_name");

    /* Allocate EC group. */
    group = (WOLFSSL_EC_GROUP*)XMALLOC(sizeof(WOLFSSL_EC_GROUP), NULL,
        DYNAMIC_TYPE_ECC);
    if (group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_new_by_curve_name malloc failure");
        err = 1;
    }

    if (!err) {
        /* Reset all fields. */
        XMEMSET(group, 0, sizeof(WOLFSSL_EC_GROUP));

        /* Set the fields of group based on the numeric ID. */
        ec_group_set_nid(group, nid);
    }

    return group;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Dispose of the EC group.
 *
 * Cannot use group after this call.
 *
 * @param [in] group  EC group to free.
 */
void wolfSSL_EC_GROUP_free(WOLFSSL_EC_GROUP *group)
{
    WOLFSSL_ENTER("wolfSSL_EC_GROUP_free");

    /* Dispose of EC group. */
    XFREE(group, NULL, DYNAMIC_TYPE_ECC);
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
#ifndef NO_BIO

/* Creates an EC group from the DER encoding.
 *
 * Only named curves supported.
 *
 * @param [out] group  Reference to EC group object.
 * @param [in]  in     Buffer holding DER encoding of curve.
 * @param [in]  inSz   Length of data in buffer.
 * @return  EC group on success.
 * @return  NULL on error.
 */
static WOLFSSL_EC_GROUP* wolfssl_ec_group_d2i(WOLFSSL_EC_GROUP** group,
    const unsigned char** in_pp, long inSz)
{
    int err = 0;
    WOLFSSL_EC_GROUP* ret = NULL;
    word32 idx = 0;
    word32 oid = 0;
    int id = 0;
    const unsigned char* in;

    if (in_pp == NULL || *in_pp == NULL)
        return NULL;

    in = *in_pp;

    /* Use the group passed in. */
    if ((group != NULL) && (*group != NULL)) {
        ret = *group;
    }

    /* Only support named curves. */
    if (in[0] != ASN_OBJECT_ID) {
        WOLFSSL_ERROR_MSG("Invalid or unsupported encoding");
        err = 1;
    }
    /* Decode the OBJECT ID - expecting an EC curve OID. */
    if ((!err) && (GetObjectId(in, &idx, &oid, oidCurveType, (word32)inSz) !=
            0)) {
        err = 1;
    }
    if (!err) {
        /* Get the internal ID for OID. */
        id = wc_ecc_get_oid(oid, NULL, NULL);
        if (id < 0) {
            err = 1;
        }
    }
    if (!err) {
        /* Get the NID for the internal ID. */
        int nid = EccEnumToNID(id);
        if (ret == NULL) {
            /* Create a new EC group with the numeric ID. */
            ret = wolfSSL_EC_GROUP_new_by_curve_name(nid);
            if (ret == NULL) {
                err = 1;
            }
        }
        else {
            ec_group_set_nid(ret, nid);
        }
    }
    if ((!err) && (group != NULL)) {
        /* Return the EC group through reference. */
        *group = ret;
    }

    if (err) {
        if ((ret != NULL) && (ret != *group)) {
            wolfSSL_EC_GROUP_free(ret);
        }
        ret = NULL;
    }
    else {
        *in_pp += idx;
    }
    return ret;
}

/* Creates a new EC group from the PEM encoding in the BIO.
 *
 * @param [in]  bio    BIO to read PEM encoding from.
 * @param [out] group  Reference to EC group object.
 * @param [in]  cb     Password callback when PEM encrypted.
 * @param [in]  pass   NUL terminated string for passphrase when PEM encrypted.
 * @return  EC group on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_GROUP* wolfSSL_PEM_read_bio_ECPKParameters(WOLFSSL_BIO* bio,
    WOLFSSL_EC_GROUP** group, wc_pem_password_cb* cb, void* pass)
{
    int err = 0;
    WOLFSSL_EC_GROUP* ret = NULL;
    DerBuffer*        der = NULL;
    int               keyFormat = 0;

     if (bio == NULL) {
         err = 1;
     }

    /* Read parameters from BIO and convert PEM to DER. */
    if ((!err) && (pem_read_bio_key(bio, cb, pass, ECC_PARAM_TYPE,
            &keyFormat, &der) < 0)) {
        err = 1;
    }
    if (!err) {
        /* Create EC group from DER encoding. */
        const byte** p = (const byte**)&der->buffer;
        ret = wolfssl_ec_group_d2i(group, p, der->length);
        if (ret == NULL) {
            WOLFSSL_ERROR_MSG("Error loading DER buffer into WOLFSSL_EC_GROUP");
        }
    }

    /* Dispose of any allocated data. */
    FreeDer(&der);
    return ret;
}

WOLFSSL_EC_GROUP *wolfSSL_d2i_ECPKParameters(WOLFSSL_EC_GROUP **out,
        const unsigned char **in, long len)
{
    return wolfssl_ec_group_d2i(out, in, len);
}

int wolfSSL_i2d_ECPKParameters(const WOLFSSL_EC_GROUP* grp, unsigned char** pp)
{
    unsigned char* out = NULL;
    int len = 0;
    int idx;
    const byte* oid = NULL;
    word32 oidSz = 0;

    if (grp == NULL || !wc_ecc_is_valid_idx(grp->curve_idx) ||
            grp->curve_idx < 0)
        return WOLFSSL_FATAL_ERROR;

    /* Get the actual DER encoding of the OID. ecc_sets[grp->curve_idx].oid
     * is just the numerical representation. */
    if (wc_ecc_get_oid((word32)grp->curve_oid, &oid, &oidSz) < 0)
        return WOLFSSL_FATAL_ERROR;

    len = SetObjectId((int)oidSz, NULL) + (int)oidSz;

    if (pp == NULL)
        return len;

    if (*pp == NULL) {
        out = (unsigned char*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_ASN1);
        if (out == NULL)
            return WOLFSSL_FATAL_ERROR;
    }
    else {
        out = *pp;
    }

    idx = SetObjectId((int)oidSz, out);
    XMEMCPY(out + idx, oid, oidSz);
    if (*pp == NULL)
        *pp = out;
    else
        *pp += len;

    return len;
}
#endif /* !NO_BIO */

#if defined(OPENSSL_ALL) && !defined(NO_CERTS)
/* Copy an EC group.
 *
 * Only used by wolfSSL_EC_KEY_dup at this time.
 *
 * @param [in, out] dst  Destination EC group.
 * @param [in]      src  Source EC group.
 * @return  0 on success.
 */
static int wolfssl_ec_group_copy(WOLFSSL_EC_GROUP* dst,
    const WOLFSSL_EC_GROUP* src)
{
    /* Copy the fields. */
    dst->curve_idx = src->curve_idx;
    dst->curve_nid = src->curve_nid;
    dst->curve_oid = src->curve_oid;

    return 0;
}
#endif /* OPENSSL_ALL && !NO_CERTS */

/* Copies ecc_key into new WOLFSSL_EC_GROUP object
 *
 * @param [in] src  EC group to duplicate.
 *
 * @return  EC group on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_GROUP* wolfSSL_EC_GROUP_dup(const WOLFSSL_EC_GROUP *src)
{
    WOLFSSL_EC_GROUP* newGroup = NULL;

    if (src != NULL) {
        /* Create new group base on NID in original EC group. */
        newGroup = wolfSSL_EC_GROUP_new_by_curve_name(src->curve_nid);
     }

    return newGroup;
}

/* Compare two EC groups.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] a    First EC group.
 * @param [in] b    Second EC group.
 * @param [in] ctx  Big number context to use when comparing fields. Unused.
 *
 * @return  0 if equal.
 * @return  1 if not equal.
 * @return  -1 on error.
 */
int wolfSSL_EC_GROUP_cmp(const WOLFSSL_EC_GROUP *a, const WOLFSSL_EC_GROUP *b,
                         WOLFSSL_BN_CTX *ctx)
{
    int ret;

    /* No BN operations performed. */
    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_cmp");

    /* Validate parameters. */
    if ((a == NULL) || (b == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_cmp Bad arguments");
        /* Return error value. */
        ret = WOLFSSL_FATAL_ERROR;
    }
    /* Compare NID and wolfSSL curve index. */
    else {
        /* 0 when same, 1 when not. */
        ret = ((a->curve_nid == b->curve_nid) &&
               (a->curve_idx == b->curve_idx)) ? 0 : 1;
    }

    return ret;
}

#ifndef NO_WOLFSSL_STUB
/* Set the ASN.1 flag that indicate encoding of curve.
 *
 * Stub function - flag not used elsewhere.
 * Always encoded as named curve.
 *
 * @param [in] group  EC group to modify.
 * @param [in] flag   ASN.1 flag to set. Valid values:
 *                    OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE
 */
void wolfSSL_EC_GROUP_set_asn1_flag(WOLFSSL_EC_GROUP *group, int flag)
{
    (void)group;
    (void)flag;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_set_asn1_flag");
    WOLFSSL_STUB("EC_GROUP_set_asn1_flag");
}
#endif

/* Get the curve NID of the group.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] group  EC group.
 * @return  Curve NID on success.
 * @return  0 on error.
 */
int wolfSSL_EC_GROUP_get_curve_name(const WOLFSSL_EC_GROUP *group)
{
    int nid = 0;
    WOLFSSL_ENTER("wolfSSL_EC_GROUP_get_curve_name");

    if (group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_curve_name Bad arguments");
    }
    else {
        nid = group->curve_nid;
    }

    return nid;
}

/* Get the degree (curve size in bits) of the EC group.
 *
 * Return code compliant with OpenSSL.
 *
 * @return  Degree of the curve on success.
 * @return  0 on error.
 */
int wolfSSL_EC_GROUP_get_degree(const WOLFSSL_EC_GROUP *group)
{
    int degree = 0;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_get_degree");

    if (group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_degree Bad arguments");
    }
    else {
        switch (group->curve_nid) {
            case WC_NID_secp112r1:
            case WC_NID_secp112r2:
                degree = 112;
                break;
            case WC_NID_secp128r1:
            case WC_NID_secp128r2:
                degree = 128;
                break;
            case WC_NID_secp160k1:
            case WC_NID_secp160r1:
            case WC_NID_secp160r2:
            case WC_NID_brainpoolP160r1:
                degree = 160;
                break;
            case WC_NID_secp192k1:
            case WC_NID_brainpoolP192r1:
            case WC_NID_X9_62_prime192v1:
            case WC_NID_X9_62_prime192v2:
            case WC_NID_X9_62_prime192v3:
                degree = 192;
                break;
            case WC_NID_secp224k1:
            case WC_NID_secp224r1:
            case WC_NID_brainpoolP224r1:
                degree = 224;
                break;
            case WC_NID_X9_62_prime239v1:
            case WC_NID_X9_62_prime239v2:
            case WC_NID_X9_62_prime239v3:
                degree = 239;
                break;
            case WC_NID_secp256k1:
            case WC_NID_brainpoolP256r1:
            case WC_NID_X9_62_prime256v1:
                degree = 256;
                break;
            case WC_NID_brainpoolP320r1:
                degree = 320;
                break;
            case WC_NID_secp384r1:
            case WC_NID_brainpoolP384r1:
                degree = 384;
                break;
            case WC_NID_brainpoolP512r1:
                degree = 512;
                break;
            case WC_NID_secp521r1:
                degree = 521;
                break;
        }
    }

    return degree;
}
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Get the length of the order in bits of the EC group.
 *
 * TODO: consider switch statement or calculating directly from hex string
 * array instead of using mp_int.
 *
 * @param [in] group  EC group.
 * @return  Length of order in bits on success.
 * @return  0 on error.
 */
int wolfSSL_EC_GROUP_order_bits(const WOLFSSL_EC_GROUP *group)
{
    int ret = 0;
    WC_DECLARE_VAR(order, mp_int, 1, 0);

    /* Validate parameter. */
    if ((group == NULL) || (group->curve_idx < 0)) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_order_bits NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        /* Allocate memory for mp_int that will hold order value. */
        order = (mp_int *)XMALLOC(sizeof(*order), NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (order == NULL) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#endif

    if (ret == 0) {
        /* Initialize mp_int. */
        ret = mp_init(order);
    }

    if (ret == 0) {
        /* Read hex string of order from wolfCrypt array of curves. */
        ret = mp_read_radix(order, ecc_sets[group->curve_idx].order,
            MP_RADIX_HEX);
        if (ret == 0) {
            /* Get bits of order. */
            ret = mp_count_bits(order);
        }
        /* Clear and free mp_int. */
        mp_clear(order);
    }

    WC_FREE_VAR_EX(order, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    /* Convert error code to length of 0. */
    if (ret < 0) {
        ret = 0;
    }

    return ret;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA)
/* Get the order of the group as a BN.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in]      group  EC group.
 * @param [in, out] order  BN to hold order value.
 * @param [in]      ctx    Context to use for BN operations. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_EC_GROUP_get_order(const WOLFSSL_EC_GROUP *group,
    WOLFSSL_BIGNUM *order, WOLFSSL_BN_CTX *ctx)
{
    int ret = 1;
    mp_int* mp = NULL;

    /* No BN operations performed - done with mp_int in BN. */
    (void)ctx;

    /* Validate parameters. */
    if ((group == NULL) || (order == NULL) || (order->internal == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_order NULL error");
        ret = 0;
    }

    if (ret == 1 &&
            (group->curve_idx < 0 || !wc_ecc_is_valid_idx(group->curve_idx))) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_order Bad group idx");
        ret = 0;
    }

    if (ret == 1) {
        mp = (mp_int*)order->internal;
    }
    /* Initialize */
    if ((ret == 1) && (mp_init(mp) != MP_OKAY)) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_order mp_init failure");
        ret = 0;
    }
    /* Read hex string of order from wolfCrypt array of curves. */
    if ((ret == 1) && (mp_read_radix(mp, ecc_sets[group->curve_idx].order,
            MP_RADIX_HEX) != MP_OKAY)) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_order mp_read order failure");
        /* Zero out any partial value but don't free. */
        mp_zero(mp);
        ret = 0;
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

/* End EC_GROUP */

/* Start EC_POINT */

#if defined(OPENSSL_EXTRA)

/* Set data of EC point into internal, wolfCrypt EC point object.
 *
 * EC_POINT Openssl -> WolfSSL
 *
 * @param [in, out] p  EC point to update.
 * @return  1 on success.
 * @return  -1 on failure.
 */
static int ec_point_internal_set(WOLFSSL_EC_POINT *p)
{
    int ret = 1;

    WOLFSSL_ENTER("ec_point_internal_set");

    /* Validate parameter. */
    if ((p == NULL) || (p->internal == NULL)) {
        WOLFSSL_MSG("ECPoint NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        /* Get internal point as a wolfCrypt EC point. */
        ecc_point* point = (ecc_point*)p->internal;

        /* Set X ordinate if available. */
        if ((p->X != NULL) && (wolfssl_bn_get_value(p->X, point->x) != 1)) {
            WOLFSSL_MSG("ecc point X error");
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* Set Y ordinate if available. */
        if ((ret == 1) && (p->Y != NULL) && (wolfssl_bn_get_value(p->Y,
                point->y) != 1)) {
            WOLFSSL_MSG("ecc point Y error");
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* Set Z ordinate if available. */
        if ((ret == 1) && (p->Z != NULL) && (wolfssl_bn_get_value(p->Z,
                point->z) != 1)) {
            WOLFSSL_MSG("ecc point Z error");
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* Internal values set when operations succeeded. */
        p->inSet = (ret == 1);
    }

    return ret;
}

/* Set data of internal, wolfCrypt EC point object into EC point.
 *
 * EC_POINT WolfSSL -> OpenSSL
 *
 * @param [in, out] p  EC point to update.
 * @return  1 on success.
 * @return  -1 on failure.
 */
static int ec_point_external_set(WOLFSSL_EC_POINT *p)
{
    int ret = 1;

    WOLFSSL_ENTER("ec_point_external_set");

    /* Validate parameter. */
    if ((p == NULL) || (p->internal == NULL)) {
        WOLFSSL_MSG("ECPoint NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        /* Get internal point as a wolfCrypt EC point. */
        ecc_point* point = (ecc_point*)p->internal;

        /* Set X ordinate. */
        if (wolfssl_bn_set_value(&p->X, point->x) != 1) {
            WOLFSSL_MSG("ecc point X error");
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* Set Y ordinate. */
        if ((ret == 1) && (wolfssl_bn_set_value(&p->Y, point->y) != 1)) {
            WOLFSSL_MSG("ecc point Y error");
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* Set Z ordinate. */
        if ((ret == 1) && (wolfssl_bn_set_value(&p->Z, point->z) != 1)) {
            WOLFSSL_MSG("ecc point Z error");
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* External values set when operations succeeded. */
        p->exSet = (ret == 1);
    }

    return ret;
}

/* Setup internals of EC point.
 *
 * Assumes point is not NULL.
 *
 * @param [in, out] point  EC point to update.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int ec_point_setup(const WOLFSSL_EC_POINT *point) {
    int ret = 1;

    /* Check if internal values need setting. */
    if (!point->inSet) {
        WOLFSSL_MSG("No ECPoint internal set, do it");

        /* Forcing to non-constant type to update internals. */
        if (ec_point_internal_set((WOLFSSL_EC_POINT *)point) != 1) {
            WOLFSSL_MSG("ec_point_internal_set failed");
            ret = 0;
        }
    }

    return ret;
}

/* Create a new EC point from the group.
 *
 * @param [in] group  EC group.
 * @return  EC point on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_POINT* wolfSSL_EC_POINT_new(const WOLFSSL_EC_GROUP* group)
{
    int err = 0;
    WOLFSSL_EC_POINT* point = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_new");

    /* Validate parameter. */
    if (group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_new NULL error");
        err = 1;
    }

    if (!err) {
        /* Allocate memory for new EC point. */
        point = (WOLFSSL_EC_POINT*)XMALLOC(sizeof(WOLFSSL_EC_POINT), NULL,
            DYNAMIC_TYPE_ECC);
        if (point == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_new malloc ecc point failure");
            err = 1;
        }
    }
    if (!err) {
        /* Clear fields of EC point. */
        XMEMSET(point, 0, sizeof(WOLFSSL_EC_POINT));

        /* Allocate internal EC point. */
        point->internal = wc_ecc_new_point();
        if (point->internal == NULL) {
            WOLFSSL_MSG("ecc_new_point failure");
            err = 1;
        }
    }

    if (err) {
        XFREE(point, NULL, DYNAMIC_TYPE_ECC);
        point = NULL;
    }
    return point;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Dispose of the EC point.
 *
 * Cannot use point after this call.
 *
 * @param [in, out] point  EC point to free.
 */
void wolfSSL_EC_POINT_free(WOLFSSL_EC_POINT *point)
{
    WOLFSSL_ENTER("wolfSSL_EC_POINT_free");

    if (point != NULL) {
        if (point->internal != NULL) {
            wc_ecc_del_point((ecc_point*)point->internal);
            point->internal = NULL;
        }

        /* Free ordinates. */
        wolfSSL_BN_free(point->X);
        wolfSSL_BN_free(point->Y);
        wolfSSL_BN_free(point->Z);
        /* Clear fields. */
        point->X = NULL;
        point->Y = NULL;
        point->Z = NULL;
        point->inSet = 0;
        point->exSet = 0;

        /* Dispose of EC point. */
        XFREE(point, NULL, DYNAMIC_TYPE_ECC);
    }
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA

/* Clear and dispose of the EC point.
 *
 * Cannot use point after this call.
 *
 * @param [in, out] point  EC point to free.
 */
void wolfSSL_EC_POINT_clear_free(WOLFSSL_EC_POINT *point)
{
    WOLFSSL_ENTER("wolfSSL_EC_POINT_clear_free");

    if (point != NULL) {
        if (point->internal != NULL) {
            /* Force internal point to be zeros. */
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
            wc_ecc_forcezero_point((ecc_point*)point->internal);
    #else
            ecc_point* p = (ecc_point*)point->internal;
            mp_forcezero(p->x);
            mp_forcezero(p->y);
            mp_forcezero(p->z);
    #endif
            wc_ecc_del_point((ecc_point*)point->internal);
            point->internal = NULL;
        }

        /* Clear the ordinates before freeing. */
        wolfSSL_BN_clear_free(point->X);
        wolfSSL_BN_clear_free(point->Y);
        wolfSSL_BN_clear_free(point->Z);
        /* Clear fields. */
        point->X = NULL;
        point->Y = NULL;
        point->Z = NULL;
        point->inSet = 0;
        point->exSet = 0;

        /* Dispose of EC point. */
        XFREE(point, NULL, DYNAMIC_TYPE_ECC);
    }
}

/* Print out the internals of EC point in debug and when logging callback set.
 *
 * Not an OpenSSL API.
 *
 * TODO: Use WOLFSSL_MSG_EX()?
 *
 * @param [in] msg    Message to prepend.
 * @param [in] point  EC point to print.
 */
void wolfSSL_EC_POINT_dump(const char *msg, const WOLFSSL_EC_POINT *point)
{
#if defined(DEBUG_WOLFSSL)
    char *num;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_dump");

    /* Only print when debugging on. */
    if (WOLFSSL_IS_DEBUG_ON()) {
        if (point == NULL) {
            /* No point passed in so just put out "NULL". */
            WOLFSSL_MSG_EX("%s = NULL\n", msg);
        }
        else {
            /* Put out message and status of internal/external data set. */
            WOLFSSL_MSG_EX("%s:\n\tinSet=%d, exSet=%d\n", msg, point->inSet,
                point->exSet);
            /* Get x-ordinate as a hex string and print. */
            num = wolfSSL_BN_bn2hex(point->X);
            WOLFSSL_MSG_EX("\tX = %s\n", num);
            XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
            /* Get x-ordinate as a hex string and print. */
            num = wolfSSL_BN_bn2hex(point->Y);
            WOLFSSL_MSG_EX("\tY = %s\n", num);
            XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
            /* Get z-ordinate as a hex string and print. */
            num = wolfSSL_BN_bn2hex(point->Z);
            WOLFSSL_MSG_EX("\tZ = %s\n", num);
            XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
        }
    }
#else
    (void)msg;
    (void)point;
#endif
}

/* Convert EC point to hex string that as either uncompressed or compressed.
 *
 * ECC point compression types were not included in selftest ecc.h
 *
 * @param [in] group  EC group for point.
 * @param [in] point  EC point to encode.
 * @param [in] form   Format of encoding. Valid values:
 *                    POINT_CONVERSION_UNCOMPRESSED, POINT_CONVERSION_COMPRESSED
 * @param [in] ctx    Context to use for BN operations. Unused.
 * @return  Allocated hex string on success.
 * @return  NULL on error.
 */
char* wolfSSL_EC_POINT_point2hex(const WOLFSSL_EC_GROUP* group,
    const WOLFSSL_EC_POINT* point, int form, WOLFSSL_BN_CTX* ctx)
{
    static const char* hexDigit = "0123456789ABCDEF";
    char* hex = NULL;
    int i;
    int sz = 0;
    int len = 0;
    int err = 0;

    /* No BN operations performed. */
    (void)ctx;

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL)) {
        err = 1;
    }
    /* Get curve id expects a positive index. */
    if ((!err) && (group->curve_idx < 0)) {
        err = 1;
    }

    if (!err) {
        /* Get curve id to look up ordinate size. */
        int id = wc_ecc_get_curve_id(group->curve_idx);
        /* Get size of ordinate. */
        if ((sz = wc_ecc_get_curve_size_from_id(id)) < 0) {
            err = 1;
        }
    }
    if (!err) {
        /* <format byte> <x-ordinate> [<y-ordinate>] */
        len = sz + 1;
        if (form == WC_POINT_CONVERSION_UNCOMPRESSED) {
            /* Include y ordinate when uncompressed. */
            len += sz;
        }

        /* Hex string: allocate 2 bytes to represent each byte plus 1 for '\0'.
         */
        hex = (char*)XMALLOC((size_t)(2 * len + 1), NULL, DYNAMIC_TYPE_ECC);
        if (hex == NULL) {
            err = 1;
        }
    }
    if (!err) {
        /* Make bytes all zeros to allow for ordinate values less than max size.
         */
        XMEMSET(hex, 0, (size_t)(2 * len + 1));

        /* Calculate offset as leading zeros not encoded. */
        i = sz - mp_unsigned_bin_size((mp_int*)point->X->internal) + 1;
        /* Put in x-ordinate after format byte. */
        if (mp_to_unsigned_bin((mp_int*)point->X->internal, (byte*)(hex + i)) <
                0) {
            err = 1;
        }
    }
    if (!err) {
        if (form == WC_POINT_CONVERSION_COMPRESSED) {
            /* Compressed format byte value dependent on whether y-ordinate is
             * odd.
             */
            hex[0] = mp_isodd((mp_int*)point->Y->internal) ?
                ECC_POINT_COMP_ODD : ECC_POINT_COMP_EVEN;
            /* No y-ordinate. */
        }
        else {
            /* Put in uncompressed format byte. */
            hex[0] = ECC_POINT_UNCOMP;
            /* Calculate offset as leading zeros not encoded. */
            i = 1 + 2 * sz - mp_unsigned_bin_size((mp_int*)point->Y->internal);
            /* Put in y-ordinate after x-ordinate. */
            if (mp_to_unsigned_bin((mp_int*)point->Y->internal,
                    (byte*)(hex + i)) < 0) {
                err = 1;
            }
        }
    }
    if (!err) {
        /* Convert binary encoding to hex string. */
        /* Start at end so as not to overwrite. */
        for (i = len-1; i >= 0; i--) {
            /* Get byte value and store has hex string. */
            byte b = (byte)hex[i];
            hex[i * 2 + 1] = hexDigit[b  & 0xf];
            hex[i * 2    ] = hexDigit[b >>   4];
        }
        /* Memset put trailing zero or '\0' on end of string. */
    }

    if (err && (hex != NULL)) {
        /* Dispose of allocated data not being returned. */
        XFREE(hex,  NULL, DYNAMIC_TYPE_ECC);
        hex = NULL;
    }
    /* Return hex string encoding. */
    return hex;
}

static size_t hex_to_bytes(const char *hex, unsigned char *output, size_t sz)
{
    word32 i;
    for (i = 0; i < sz; i++) {
        signed char ch1, ch2;
        ch1 = HexCharToByte(hex[i * 2]);
        ch2 = HexCharToByte(hex[i * 2 + 1]);
        if ((ch1 < 0) || (ch2 < 0)) {
            WOLFSSL_MSG("hex_to_bytes: syntax error");
            return 0;
        }
        output[i] = (unsigned char)((ch1 << 4) + ch2);
    }
    return sz;
}

WOLFSSL_EC_POINT* wolfSSL_EC_POINT_hex2point(const WOLFSSL_EC_GROUP *group,
            const char *hex, WOLFSSL_EC_POINT*p, WOLFSSL_BN_CTX *ctx)
{
    /* for uncompressed mode */
    size_t str_sz;
    WOLFSSL_BIGNUM *Gx  = NULL;
    WOLFSSL_BIGNUM *Gy  = NULL;
    char   strGx[MAX_ECC_BYTES * 2 + 1];

    /* for compressed mode */
    int    key_sz;
    byte   *octGx = (byte *)strGx; /* octGx[MAX_ECC_BYTES] */

    int p_alloc = 0;
    int ret;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_hex2point");

    if (group == NULL || hex == NULL || ctx == NULL)
        return NULL;

    if (p == NULL) {
        if ((p = wolfSSL_EC_POINT_new(group)) == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_new");
            goto err;
        }
        p_alloc = 1;
    }

    key_sz = (wolfSSL_EC_GROUP_get_degree(group) + 7) / 8;
    if (hex[0] ==  '0' && hex[1] == '4') { /* uncompressed mode */
        str_sz = (size_t)key_sz * 2;

        XMEMSET(strGx, 0x0, str_sz + 1);
        XMEMCPY(strGx, hex + 2, str_sz);

        if (wolfSSL_BN_hex2bn(&Gx, strGx) == 0)
            goto err;

        if (wolfSSL_BN_hex2bn(&Gy, hex + 2 + str_sz) == 0)
            goto err;

        ret = wolfSSL_EC_POINT_set_affine_coordinates_GFp
                                            (group, p, Gx, Gy, ctx);

        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_set_affine_coordinates_GFp");
            goto err;
        }
    }
    else if (hex[0] == '0' && (hex[1] == '2' || hex[1] == '3')) {
        size_t sz = XSTRLEN(hex + 2) / 2;
        /* compressed mode */
        octGx[0] = ECC_POINT_COMP_ODD;
        if (hex_to_bytes(hex + 2, octGx + 1, sz) != sz) {
            goto err;
        }
        if (wolfSSL_ECPoint_d2i(octGx, (word32)key_sz + 1, group, p)
                                            != WOLFSSL_SUCCESS) {
            goto err;
        }
    }
    else
        goto err;

    wolfSSL_BN_free(Gx);
    wolfSSL_BN_free(Gy);
    return p;

err:
    wolfSSL_BN_free(Gx);
    wolfSSL_BN_free(Gy);
    if (p_alloc) {
        wolfSSL_EC_POINT_free(p);
    }
    return NULL;

}

/* Encode the EC point as an uncompressed point in DER.
 *
 * Return code compliant with OpenSSL.
 * Not OpenSSL API.
 *
 * @param [in]      group  EC group point belongs to.
 * @param [in]      point  EC point to encode.
 * @param [out]     out    Buffer to encode into. May be NULL.
 * @param [in, out] len    On in, length of buffer in bytes.
 *                         On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_ECPoint_i2d(const WOLFSSL_EC_GROUP *group,
    const WOLFSSL_EC_POINT *point, unsigned char *out, unsigned int *len)
{
    int res = 1;

    WOLFSSL_ENTER("wolfSSL_ECPoint_i2d");

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL) || (len == NULL)) {
        WOLFSSL_MSG("wolfSSL_ECPoint_i2d NULL error");
        res = 0;
    }

    /* Ensure points internals are set up. */
    if ((res == 1) && (ec_point_setup(point) != 1)) {
        res = 0;
    }

    /* Dump the point if encoding. */
    if ((res == 1) && (out != NULL)) {
        wolfSSL_EC_POINT_dump("i2d p", point);
    }

    if (res == 1) {
        /* DER encode point in uncompressed format. */
        int ret = wc_ecc_export_point_der(group->curve_idx,
            (ecc_point*)point->internal, out, len);
        /* Check return. When out is NULL, return will be length only error. */
        if ((ret != MP_OKAY) && ((out != NULL) ||
                                 (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)))) {
            WOLFSSL_MSG("wolfSSL_ECPoint_i2d wc_ecc_export_point_der failed");
            res = 0;
        }
    }

    return res;
}

/* Decode the uncompressed point in DER into EC point.
 *
 * Return code compliant with OpenSSL.
 * Not OpenSSL API.
 *
 * @param [in]      in     Buffer containing DER encoded point.
 * @param [in]      len    Length of data in bytes.
 * @param [in]      group  EC group associated with point.
 * @param [in, out] point  EC point to set data into.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_ECPoint_d2i(const unsigned char *in, unsigned int len,
    const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *point)
{
    int ret = 1;
    WOLFSSL_BIGNUM* x = NULL;
    WOLFSSL_BIGNUM* y = NULL;

    WOLFSSL_ENTER("wolfSSL_ECPoint_d2i");

    /* Validate parameters. */
    if ((in == NULL) || (group == NULL) || (point == NULL) ||
            (point->internal == NULL)) {
        WOLFSSL_MSG("wolfSSL_ECPoint_d2i NULL error");
        ret = 0;
    }

    if (ret == 1) {
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
        /* Import point into internal EC point. */
        if (wc_ecc_import_point_der_ex(in, len, group->curve_idx,
                (ecc_point*)point->internal, 0) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_import_point_der_ex failed");
            ret = 0;
        }
    #else
        /* ECC_POINT_UNCOMP is not defined CAVP self test so use magic number */
        if (in[0] == 0x04) {
            /* Import point into internal EC point. */
            if (wc_ecc_import_point_der((unsigned char *)in, len,
                    group->curve_idx, (ecc_point*)point->internal) != MP_OKAY) {
                WOLFSSL_MSG("wc_ecc_import_point_der failed");
                ret = 0;
            }
        }
        else {
            WOLFSSL_MSG("Only uncompressed points supported with "
                        "HAVE_SELFTEST");
            ret = 0;
        }
    #endif
    }

    if (ret == 1)
        point->inSet = 1;

    /* Set new external point. */
    if (ret == 1 && ec_point_external_set(point) != 1) {
        WOLFSSL_MSG("ec_point_external_set failed");
        ret = 0;
    }

    if (ret == 1 && !wolfSSL_BN_is_one(point->Z)) {
#if !defined(WOLFSSL_SP_MATH) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)
        x = wolfSSL_BN_new();
        y = wolfSSL_BN_new();
        if (x == NULL || y == NULL)
            ret = 0;

        if (ret == 1 && wolfSSL_EC_POINT_get_affine_coordinates_GFp(group,
                point, x, y, NULL) != 1) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_get_affine_coordinates_GFp failed");
            ret = 0;
        }

        /* wolfSSL_EC_POINT_set_affine_coordinates_GFp check that the point is
         * on the curve. */
        if (ret == 1 && wolfSSL_EC_POINT_set_affine_coordinates_GFp(group,
                point, x, y, NULL) != 1) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_set_affine_coordinates_GFp failed");
            ret = 0;
        }
#else
        WOLFSSL_MSG("Importing non-affine point. This may cause issues in math "
                    "operations later on.");
#endif
    }

    if (ret == 1) {
        /* Dump new point. */
        wolfSSL_EC_POINT_dump("d2i p", point);
    }

    wolfSSL_BN_free(x);
    wolfSSL_BN_free(y);

    return ret;
}

/* Encode point as octet string.
 *
 * HYBRID not supported.
 *
 * @param [in]  group  EC group that point belongs to.
 * @param [in]  point  EC point to encode.
 * @param [in]  form   Format of encoding. Valid values:
 *                     POINT_CONVERSION_UNCOMPRESSED,POINT_CONVERSION_COMPRESSED
 * @param [out] buf    Buffer to write encoding into.
 * @param [in]  len    Length of buffer.
 * @param [in]  ctx    Context to use for BN operations. Unused.
 * @return  Length of encoded data on success.
 * @return  0 on error.
 */
size_t wolfSSL_EC_POINT_point2oct(const WOLFSSL_EC_GROUP *group,
   const WOLFSSL_EC_POINT *point, int form, byte *buf, size_t len,
   WOLFSSL_BN_CTX *ctx)
{
    int err = 0;
    word32 enc_len = (word32)len;
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
    int compressed = ((form == WC_POINT_CONVERSION_COMPRESSED) ? 1 : 0);
#endif /* !HAVE_SELFTEST */

    WOLFSSL_ENTER("wolfSSL_EC_POINT_point2oct");

    /* No BN operations performed. */
    (void)ctx;

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL)) {
        err = 1;
    }

    /* Ensure points internals are set up. */
    if ((!err) && (ec_point_setup(point) != 1)) {
        err = 1;
    }

    /* Special case when point is infinity. */
    if ((!err) && wolfSSL_EC_POINT_is_at_infinity(group, point)) {
        /* Encoding is a single octet: 0x00. */
        enc_len = 1;
        if (buf != NULL) {
            /* Check whether buffer has space. */
            if (len < 1) {
                wolfSSL_ECerr(WOLFSSL_EC_F_EC_GFP_SIMPLE_POINT2OCT, BUFFER_E);
                err = 1;
            }
            else {
                /* Put in encoding of infinity. */
                buf[0] = 0x00;
            }
        }
    }
    /* Not infinity. */
    else if (!err) {
        /* Validate format. */
        if (form != WC_POINT_CONVERSION_UNCOMPRESSED
        #ifndef HAVE_SELFTEST
                && form != WC_POINT_CONVERSION_COMPRESSED
        #endif /* !HAVE_SELFTEST */
            ) {
            WOLFSSL_MSG("Unsupported point form");
            err = 1;
        }

        if (!err) {
            int ret;

    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
            /* Encode as compressed or uncompressed. */
            ret = wc_ecc_export_point_der_ex(group->curve_idx,
                (ecc_point*)point->internal, buf, &enc_len, compressed);
    #else
            /* Encode uncompressed point in DER format. */
            ret = wc_ecc_export_point_der(group->curve_idx,
                (ecc_point*)point->internal, buf, &enc_len);
    #endif /* !HAVE_SELFTEST */
            /* Check return. When buf is NULL, return will be length only
             * error.
             */
            if (ret != ((buf != NULL) ? MP_OKAY :
                                        WC_NO_ERR_TRACE(LENGTH_ONLY_E))) {
                err = 1;
            }
        }
    }

#if defined(DEBUG_WOLFSSL)
    if (!err) {
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_point2oct point", point);
        WOLFSSL_MSG("\twolfSSL_EC_POINT_point2oct output:");
        WOLFSSL_BUFFER(buf, enc_len);
    }
#endif

    /* On error, return encoding length of 0. */
    if (err) {
        enc_len = 0;
    }
    return (size_t)enc_len;
}


/* Convert octet string to EC point.
 *
 * @param [in]      group  EC group.
 * @param [in, out] point  EC point to set data into.
 * @param [in]      buf    Buffer holding octet string.
 * @param [in]      len    Length of data in buffer in bytes.
 * @param [in]      ctx    Context to use for BN operations. Unused.
 */
int wolfSSL_EC_POINT_oct2point(const WOLFSSL_EC_GROUP *group,
    WOLFSSL_EC_POINT *point, const unsigned char *buf, size_t len,
    WOLFSSL_BN_CTX *ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_oct2point");

    /* No BN operations performed. */
    (void)ctx;

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL)) {
        ret = 0;
    }
    else {
        /* Decode DER encoding into EC point. */
        ret = wolfSSL_ECPoint_d2i((unsigned char*)buf, (unsigned int)len, group,
            point);
    }

    return ret;
}

/* Convert an EC point to a single BN.
 *
 * @param [in]      group  EC group.
 * @param [in]      point  EC point.
 * @param [in]      form   Format of encoding. Valid values:
 *                         WC_POINT_CONVERSION_UNCOMPRESSED,
 *                         WC_POINT_CONVERSION_COMPRESSED.
 * @param [in, out] bn     BN to hold point value.
 *                         When NULL a new BN is allocated otherwise this is
 *                         returned on success.
 * @param [in]      ctx    Context to use for BN operations. Unused.
 * @return  BN object with point as a value on success.
 * @return  NULL on error.
 */
WOLFSSL_BIGNUM *wolfSSL_EC_POINT_point2bn(const WOLFSSL_EC_GROUP* group,
    const WOLFSSL_EC_POINT* point, int form, WOLFSSL_BIGNUM* bn,
    WOLFSSL_BN_CTX* ctx)
{
    int err = 0;
    size_t len = 0;
    byte *buf = NULL;
    WOLFSSL_BIGNUM *ret = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_oct2point");

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL)) {
        err = 1;
    }

    /* Calculate length of octet encoding. */
    if ((!err) && ((len = wolfSSL_EC_POINT_point2oct(group, point, form, NULL,
            0, ctx)) == 0)) {
        err = 1;
    }
    /* Allocate buffer to hold octet encoding. */
    if ((!err) && ((buf = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER)) ==
            NULL)) {
        WOLFSSL_MSG("malloc failed");
        err = 1;
    }
    /* Encode EC point as an octet string. */
    if ((!err) && (wolfSSL_EC_POINT_point2oct(group, point, form, buf, len,
            ctx) != len)) {
        err = 1;
    }
    /* Load BN with octet string data. */
    if (!err) {
        ret = wolfSSL_BN_bin2bn(buf, (int)len, bn);
    }

    /* Dispose of any allocated data. */
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#if defined(USE_ECC_B_PARAM) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
/* Check if EC point is on the the curve defined by the EC group.
 *
 * @param [in] group  EC group defining curve.
 * @param [in] point  EC point to check.
 * @param [in] ctx    Context to use for BN operations. Unused.
 * @return  1 when point is on curve.
 * @return  0 when point is not on curve or error.
 */
int wolfSSL_EC_POINT_is_on_curve(const WOLFSSL_EC_GROUP *group,
    const WOLFSSL_EC_POINT *point, WOLFSSL_BN_CTX *ctx)
{
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_is_on_curve");

    /* No BN operations performed. */
    (void)ctx;

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL)) {
        WOLFSSL_MSG("Invalid arguments");
        err = 1;
    }

    /* Ensure internal EC point set. */
    if ((!err) && (!point->inSet) && ec_point_internal_set(
            (WOLFSSL_EC_POINT*)point) != 1) {
        WOLFSSL_MSG("ec_point_internal_set error");
        err = 1;
    }

    /* Check point is on curve from group. */
    if ((!err) && (wc_ecc_point_is_on_curve((ecc_point*)point->internal,
            group->curve_idx) != MP_OKAY)) {
        err = 1;
    }

    /* Return boolean of on curve. No error means on curve. */
    return !err;
}
#endif /* USE_ECC_B_PARAM && !HAVE_SELFTEST && !(FIPS_VERSION <= 2) */

#if !defined(WOLFSSL_SP_MATH) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)
/* Convert Jacobian ordinates to affine.
 *
 * @param [in]      group  EC group.
 * @param [in]      point  EC point to get coordinates from.
 * @return  1 on success.
 * @return  0 on error.
 */
int ec_point_convert_to_affine(const WOLFSSL_EC_GROUP *group,
    WOLFSSL_EC_POINT *point)
{
    int err = 0;
    mp_digit mp = 0;
    WC_DECLARE_VAR(modulus, mp_int, 1, 0);

    /* Allocate memory for curve's prime modulus. */
    WC_ALLOC_VAR_EX(modulus, mp_int, 1, NULL, DYNAMIC_TYPE_BIGINT, err=1);
    /* Initialize the MP integer. */
    if ((!err) && (mp_init(modulus) != MP_OKAY)) {
        WOLFSSL_MSG("mp_init failed");
        err = 1;
    }

    if (!err) {
        /* Get the modulus from the hex string in the EC curve set. */
        if (mp_read_radix(modulus, ecc_sets[group->curve_idx].prime,
                MP_RADIX_HEX) != MP_OKAY) {
            WOLFSSL_MSG("mp_read_radix failed");
            err = 1;
        }
        /* Get Montgomery multiplier for the modulus as ordinates in
         * Montgomery form.
         */
        if ((!err) && (mp_montgomery_setup(modulus, &mp) != MP_OKAY)) {
            WOLFSSL_MSG("mp_montgomery_setup failed");
            err = 1;
        }
        /* Map internal EC point from Jacobian to affine. */
        if ((!err) && (ecc_map((ecc_point*)point->internal, modulus, mp) !=
                MP_OKAY)) {
            WOLFSSL_MSG("ecc_map failed");
            err = 1;
        }
        /* Set new ordinates into external EC point. */
        if ((!err) && (ec_point_external_set((WOLFSSL_EC_POINT *)point) != 1)) {
            WOLFSSL_MSG("ec_point_external_set failed");
            err = 1;
        }

        point->exSet = !err;
        mp_clear(modulus);
    }

    WC_FREE_VAR_EX(modulus, NULL, DYNAMIC_TYPE_BIGINT);

    return err;
}

/* Get the affine coordinates of the EC point on a Prime curve.
 *
 * When z-ordinate is not one then coordinates are Jacobian and need to be
 * converted to affine before storing in BNs.
 *
 * Return code compliant with OpenSSL.
 *
 * TODO: OpenSSL doesn't change point when Jacobian. Do the same?
 *
 * @param [in]      group  EC group.
 * @param [in]      point  EC point to get coordinates from.
 * @param [in, out] x      BN to hold x-ordinate.
 * @param [in, out] y      BN to hold y-ordinate.
 * @param [in]      ctx    Context to use for BN operations. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_EC_POINT_get_affine_coordinates_GFp(const WOLFSSL_EC_GROUP* group,
    const WOLFSSL_EC_POINT* point, WOLFSSL_BIGNUM* x, WOLFSSL_BIGNUM* y,
    WOLFSSL_BN_CTX* ctx)
{
    int ret = 1;

    /* BN operations don't need context. */
    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_get_affine_coordinates_GFp");

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL) || (point->internal == NULL) ||
            (x == NULL) || (y == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_get_affine_coordinates_GFp NULL error");
        ret = 0;
    }
    /* Don't return point at infinity. */
    if ((ret == 1) && wolfSSL_EC_POINT_is_at_infinity(group, point)) {
        ret = 0;
    }

    /* Ensure internal EC point has values of external EC point. */
    if ((ret == 1) && (ec_point_setup(point) != 1)) {
        ret = 0;
    }

    /* Check whether ordinates are in Jacobian form. */
    if ((ret == 1) && (!wolfSSL_BN_is_one(point->Z))) {
        /* Convert from Jacobian to affine. */
        if (ec_point_convert_to_affine(group, (WOLFSSL_EC_POINT*)point) == 1) {
            ret = 0;
        }
    }

    /* Copy the externally set x and y ordinates. */
    if ((ret == 1) && (wolfSSL_BN_copy(x, point->X) == NULL)) {
        ret = 0;
    }
    if ((ret == 1) && (wolfSSL_BN_copy(y, point->Y) == NULL)) {
        ret = 0;
    }

    return ret;
}
#endif /* !WOLFSSL_SP_MATH && !WOLF_CRYPTO_CB_ONLY_ECC */

/* Sets the affine coordinates that belong on a prime curve.
 *
 * @param [in]      group  EC group.
 * @param [in, out] point  EC point to set coordinates into.
 * @param [in]      x      BN holding x-ordinate.
 * @param [in]      y      BN holding y-ordinate.
 * @param [in]      ctx    Context to use for BN operations. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_EC_POINT_set_affine_coordinates_GFp(const WOLFSSL_EC_GROUP* group,
    WOLFSSL_EC_POINT* point, const WOLFSSL_BIGNUM* x, const WOLFSSL_BIGNUM* y,
    WOLFSSL_BN_CTX* ctx)
{
    int ret = 1;

    /* BN operations don't need context. */
    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_set_affine_coordinates_GFp");

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL) || (point->internal == NULL) ||
            (x == NULL) || (y == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_set_affine_coordinates_GFp NULL error");
        ret = 0;
    }

    /* Ensure we have a object for x-ordinate. */
    if ((ret == 1) && (point->X == NULL) &&
            ((point->X = wolfSSL_BN_new()) == NULL)) {
        WOLFSSL_MSG("wolfSSL_BN_new failed");
        ret = 0;
    }
    /* Ensure we have a object for y-ordinate. */
    if ((ret == 1) && (point->Y == NULL) &&
            ((point->Y = wolfSSL_BN_new()) == NULL)) {
        WOLFSSL_MSG("wolfSSL_BN_new failed");
        ret = 0;
    }
    /* Ensure we have a object for z-ordinate. */
    if ((ret == 1) && (point->Z == NULL) &&
            ((point->Z = wolfSSL_BN_new()) == NULL)) {
        WOLFSSL_MSG("wolfSSL_BN_new failed");
        ret = 0;
    }

    /* Copy the x-ordinate. */
    if ((ret == 1) && ((wolfSSL_BN_copy(point->X, x)) == NULL)) {
        WOLFSSL_MSG("wolfSSL_BN_copy failed");
        ret = 0;
    }
    /* Copy the y-ordinate. */
    if ((ret == 1) && ((wolfSSL_BN_copy(point->Y, y)) == NULL)) {
        WOLFSSL_MSG("wolfSSL_BN_copy failed");
        ret = 0;
    }
    /* z-ordinate is one for affine coordinates. */
    if ((ret == 1) && ((wolfSSL_BN_one(point->Z)) == 0)) {
        WOLFSSL_MSG("wolfSSL_BN_one failed");
        ret = 0;
    }

    /* Copy the new point data to internal object. */
    if ((ret == 1) && (ec_point_internal_set((WOLFSSL_EC_POINT *)point) != 1)) {
        WOLFSSL_MSG("ec_point_internal_set failed");
        ret = 0;
    }

#if defined(USE_ECC_B_PARAM) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
    /* Check that the point is valid. */
    if ((ret == 1) && (wolfSSL_EC_POINT_is_on_curve(group,
            (WOLFSSL_EC_POINT *)point, ctx) != 1)) {
        WOLFSSL_MSG("EC_POINT_is_on_curve failed");
        ret = 0;
    }
#endif

    return ret;
}

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
/* Add two points on the same together.
 *
 * @param [in]  curveIdx  Index of curve in ecc_set.
 * @param [out] r         Result point.
 * @param [in]  p1        First point to add.
 * @param [in]  p2        Second point to add.
 * @return  1 on success.
 * @return  0 on error.
 */
static int wolfssl_ec_point_add(int curveIdx, ecc_point* r, ecc_point* p1,
    ecc_point* p2)
{
    int ret = 1;
#ifdef WOLFSSL_SMALL_STACK
    mp_int* a = NULL;
    mp_int* prime = NULL;
    mp_int* mu = NULL;
#else
    mp_int a[1];
    mp_int prime[1];
    mp_int mu[1];
#endif
    mp_digit mp = 0;
    ecc_point* montP1 = NULL;
    ecc_point* montP2 = NULL;

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 1) {
        /* Allocate memory for curve parameter: a. */
        a = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
        if (a == NULL) {
            WOLFSSL_MSG("Failed to allocate memory for mp_int a");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate memory for curve parameter: prime. */
        prime = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
        if (prime == NULL) {
            WOLFSSL_MSG("Failed to allocate memory for mp_int prime");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate memory for mu (Montgomery normalizer). */
        mu = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
        if (mu == NULL) {
            WOLFSSL_MSG("Failed to allocate memory for mp_int mu");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Zero out all MP int data in case initialization fails. */
        XMEMSET(a, 0, sizeof(mp_int));
        XMEMSET(prime, 0, sizeof(mp_int));
        XMEMSET(mu, 0, sizeof(mp_int));
    }
#endif

    /* Initialize the MP ints. */
    if ((ret == 1) && (mp_init_multi(prime, a, mu, NULL, NULL, NULL) !=
            MP_OKAY)) {
        WOLFSSL_MSG("mp_init_multi error");
        ret = 0;
    }

    /* Read the curve parameter: a. */
    if ((ret == 1) && (mp_read_radix(a, ecc_sets[curveIdx].Af, MP_RADIX_HEX) !=
            MP_OKAY)) {
        WOLFSSL_MSG("mp_read_radix a error");
        ret = 0;
    }

    /* Read the curve parameter: prime. */
    if ((ret == 1) && (mp_read_radix(prime, ecc_sets[curveIdx].prime,
            MP_RADIX_HEX) != MP_OKAY)) {
        WOLFSSL_MSG("mp_read_radix prime error");
        ret = 0;
    }

    /* Calculate the Montgomery product. */
    if ((ret == 1) && (mp_montgomery_setup(prime, &mp) != MP_OKAY)) {
        WOLFSSL_MSG("mp_montgomery_setup nqm error");
        ret = 0;
    }

    /* TODO: use the heap filed of one of the points? */
    /* Allocate new points to hold the Montgomery form values. */
    if ((ret == 1) && (((montP1 = wc_ecc_new_point_h(NULL)) == NULL) ||
            ((montP2 = wc_ecc_new_point_h(NULL)) == NULL))) {
        WOLFSSL_MSG("wc_ecc_new_point_h nqm error");
        ret = 0;
    }

    /* Calculate the Montgomery normalizer. */
    if ((ret == 1) && (mp_montgomery_calc_normalization(mu, prime) !=
            MP_OKAY)) {
        WOLFSSL_MSG("mp_montgomery_calc_normalization error");
        ret = 0;
    }

    /* Convert to Montgomery form. */
    if ((ret == 1) && (mp_cmp_d(mu, 1) == MP_EQ)) {
        /* Copy the points if the normalizer is 1.  */
        if ((wc_ecc_copy_point(p1, montP1) != MP_OKAY) ||
                (wc_ecc_copy_point(p2, montP2) != MP_OKAY)) {
            WOLFSSL_MSG("wc_ecc_copy_point error");
            ret = 0;
        }
    }
    else if (ret == 1) {
        /* Multiply each ordinate by the Montgomery normalizer.  */
        if ((mp_mulmod(p1->x, mu, prime, montP1->x) != MP_OKAY) ||
                (mp_mulmod(p1->y, mu, prime, montP1->y) != MP_OKAY) ||
                (mp_mulmod(p1->z, mu, prime, montP1->z) != MP_OKAY)) {
            WOLFSSL_MSG("mp_mulmod error");
            ret = 0;
        }
        /* Multiply each ordinate by the Montgomery normalizer.  */
        if ((mp_mulmod(p2->x, mu, prime, montP2->x) != MP_OKAY) ||
                (mp_mulmod(p2->y, mu, prime, montP2->y) != MP_OKAY) ||
                (mp_mulmod(p2->z, mu, prime, montP2->z) != MP_OKAY)) {
            WOLFSSL_MSG("mp_mulmod error");
            ret = 0;
        }
    }

    /* Perform point addition with internal EC point objects - Jacobian form
     * result.
     */
    if ((ret == 1) && (ecc_projective_add_point(montP1, montP2, r, a, prime,
            mp) != MP_OKAY)) {
        WOLFSSL_MSG("ecc_projective_add_point error");
        ret = 0;
    }

    /* Map point back to affine coordinates. Converts from Montogomery form. */
    if ((ret == 1) && (ecc_map(r, prime, mp) != MP_OKAY)) {
        WOLFSSL_MSG("ecc_map error");
        ret = 0;
    }

    /* Dispose of allocated memory. */
    mp_clear(a);
    mp_clear(prime);
    mp_clear(mu);
    wc_ecc_del_point_h(montP1, NULL);
    wc_ecc_del_point_h(montP2, NULL);
    WC_FREE_VAR_EX(a, NULL, DYNAMIC_TYPE_BIGINT);
    WC_FREE_VAR_EX(prime, NULL, DYNAMIC_TYPE_BIGINT);
    WC_FREE_VAR_EX(mu, NULL, DYNAMIC_TYPE_BIGINT);
    return ret;
}

/* Add two points on the same curve together.
 *
 * @param [in]  group  EC group.
 * @param [out] r      EC point that is result of point addition.
 * @param [in]  p1     First EC point to add.
 * @param [in]  p2     Second EC point to add.
 * @param [in]  ctx    Context to use for BN operations. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_EC_POINT_add(const WOLFSSL_EC_GROUP* group, WOLFSSL_EC_POINT* r,
    const WOLFSSL_EC_POINT* p1, const WOLFSSL_EC_POINT* p2, WOLFSSL_BN_CTX* ctx)
{
    int ret = 1;

    /* No BN operations performed. */
    (void)ctx;

    /* Validate parameters. */
    if ((group == NULL) || (r == NULL) || (p1 == NULL) || (p2 == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_add error");
        ret = 0;
    }

    /* Ensure the internal objects of the EC points are setup. */
    if ((ret == 1) && ((ec_point_setup(r) != 1) || (ec_point_setup(p1) != 1) ||
            (ec_point_setup(p2) != 1))) {
        WOLFSSL_MSG("ec_point_setup error");
        ret = 0;
    }

#ifdef DEBUG_WOLFSSL
    if (ret == 1) {
        int nid = wolfSSL_EC_GROUP_get_curve_name(group);
        const char* curve = wolfSSL_OBJ_nid2ln(nid);
        const char* nistName = wolfSSL_EC_curve_nid2nist(nid);
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_add p1", p1);
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_add p2", p2);
        if (curve != NULL)
            WOLFSSL_MSG_EX("curve name: %s", curve);
        if (nistName != NULL)
            WOLFSSL_MSG_EX("nist curve name: %s", nistName);
    }
#endif

    if (ret == 1) {
        /* Add points using wolfCrypt objects. */
        ret = wolfssl_ec_point_add(group->curve_idx, (ecc_point*)r->internal,
            (ecc_point*)p1->internal, (ecc_point*)p2->internal);
    }

    /* Copy internal EC point values out to external EC point. */
    if ((ret == 1) && (ec_point_external_set(r) != 1)) {
        WOLFSSL_MSG("ec_point_external_set error");
        ret = 0;
    }

#ifdef DEBUG_WOLFSSL
    if (ret == 1) {
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_add result", r);
    }
#endif

    return ret;
}

/* Sum the scalar multiplications of the base point and n, and q and m.
 *
 * r = base point * n + q * m
 *
 * @param [out] r      EC point that is result of operation.
 * @param [in]  b      Base point of curve.
 * @param [in]  n      Scalar to multiply by base point.
 * @param [in]  q      EC point to be scalar multiplied.
 * @param [in]  m      Scalar to multiply q by.
 * @param [in]  a      Parameter A of curve.
 * @param [in]  prime  Prime (modulus) of curve.
 * @return  1 on success.
 * @return  0 on error.
 */
static int ec_mul2add(ecc_point* r, ecc_point* b, mp_int* n, ecc_point* q,
    mp_int* m, mp_int* a, mp_int* prime)
{
    int ret = 1;
#if defined(ECC_SHAMIR) && !defined(WOLFSSL_KCAPI_ECC)
    if (ecc_mul2add(b, n, q, m, r, a, prime, NULL) != MP_OKAY) {
        WOLFSSL_MSG("ecc_mul2add error");
        ret = 0;
    }
#else
    ecc_point* tmp = NULL;
    mp_digit mp = 0;

    /* Calculate Montgomery product. */
    if (mp_montgomery_setup(prime, &mp) != MP_OKAY) {
        WOLFSSL_MSG("mp_montgomery_setup nqm error");
        ret = 0;
    }
    /* Create temporary point to hold: q * m */
    if ((ret == 1) && ((tmp = wc_ecc_new_point()) == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_new nqm error");
        ret = 0;
    }
    /* r = base point * n */
    if ((ret == 1) && (wc_ecc_mulmod(n, b, r, a, prime, 0) !=
            MP_OKAY)) {
        WOLFSSL_MSG("wc_ecc_mulmod nqm error");
        ret = 0;
    }
    /* tmp = q * m */
    if ((ret == 1) && (wc_ecc_mulmod(m, q, tmp, a, prime, 0) != MP_OKAY)) {
        WOLFSSL_MSG("wc_ecc_mulmod nqm error");
        ret = 0;
    }
    /* r = r + tmp */
    if ((ret == 1) && (ecc_projective_add_point(tmp, r, r, a, prime, mp) !=
            MP_OKAY)) {
        WOLFSSL_MSG("wc_ecc_mulmod nqm error");
        ret = 0;
    }
    /* Map point back to affine coordinates. Converts from Montogomery
     * form. */
    if ((ret == 1) && (ecc_map(r, prime, mp) != MP_OKAY)) {
        WOLFSSL_MSG("ecc_map nqm error");
        ret = 0;
    }

    /* Dispose of allocated temporary point. */
    wc_ecc_del_point(tmp);
#endif

    return ret;
}

/* Sum the scalar multiplications of the base point and n, and q and m.
 *
 * r = base point * n + q * m
 *
 * @param [in]  curveIdx  Index of curve in ecc_set.
 * @param [out] r         EC point that is result of operation.
 * @param [in]  n         Scalar to multiply by base point. May be NULL.
 * @param [in]  q         EC point to be scalar multiplied. May be NULL.
 * @param [in]  m         Scalar to multiply q by. May be NULL.
 * @return  1 on success.
 * @return  0 on error.
 */
static int wolfssl_ec_point_mul(int curveIdx, ecc_point* r, mp_int* n,
    ecc_point* q, mp_int* m)
{
    int ret = 1;
#ifdef WOLFSSL_SMALL_STACK
    mp_int* a = NULL;
    mp_int* prime = NULL;
#else
    mp_int a[1], prime[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate MP integer for curve parameter: a. */
    a = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (a == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        /* Allocate MP integer for curve parameter: prime. */
        prime = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
        if (prime == NULL)  {
            ret = 0;
        }
    }
#endif

    /* Initialize the MP ints. */
    if ((ret == 1) && (mp_init_multi(prime, a, NULL, NULL, NULL, NULL) !=
             MP_OKAY)) {
        WOLFSSL_MSG("mp_init_multi error");
        ret = 0;
    }

    /* Read the curve parameter: prime. */
    if ((ret == 1) && (mp_read_radix(prime, ecc_sets[curveIdx].prime,
            MP_RADIX_HEX) != MP_OKAY)) {
        WOLFSSL_MSG("mp_read_radix prime error");
        ret = 0;
    }

    /* Read the curve parameter: a. */
    if ((ret == 1) && (mp_read_radix(a, ecc_sets[curveIdx].Af,
            MP_RADIX_HEX) != MP_OKAY)) {
        WOLFSSL_MSG("mp_read_radix a error");
        ret = 0;
    }

    if ((ret == 1) && (n != NULL)) {
        /* Get generator - base point. */
    #if !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
        if ((ret == 1) && (wc_ecc_get_generator(r, curveIdx) != MP_OKAY)) {
            WOLFSSL_MSG("wc_ecc_get_generator error");
            ret = 0;
        }
    #else
        /* wc_ecc_get_generator is not defined in the FIPS v2 module. */
        /* Read generator (base point) x-ordinate. */
        if ((ret == 1) && (mp_read_radix(r->x, ecc_sets[curveIdx].Gx,
                MP_RADIX_HEX) != MP_OKAY)) {
            WOLFSSL_MSG("mp_read_radix Gx error");
            ret = 0;
        }
        /* Read generator (base point) y-ordinate. */
        if ((ret == 1) && (mp_read_radix(r->y, ecc_sets[curveIdx].Gy,
                MP_RADIX_HEX) != MP_OKAY)) {
            WOLFSSL_MSG("mp_read_radix Gy error");
            ret = 0;
        }
        /* z-ordinate is one as point is affine. */
        if ((ret == 1) && (mp_set(r->z, 1) != MP_OKAY)) {
            WOLFSSL_MSG("mp_set Gz error");
            ret = 0;
        }
    #endif /* NOPT_FIPS_VERSION == 2 */
    }

    if ((ret == 1) && (n != NULL) && (q != NULL) && (m != NULL)) {
        /* r = base point * n + q * m */
        ret = ec_mul2add(r, r, n, q, m, a, prime);
    }
    /* Not all values present, see if we are only doing base point * n. */
    else if ((ret == 1) && (n != NULL)) {
        /* r = base point * n */
        if (wc_ecc_mulmod(n, r, r, a, prime, 1) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_mulmod gn error");
            ret = 0;
        }
    }
    /* Not all values present, see if we are only doing q * m. */
    else if ((ret == 1) && (q != NULL) && (m != NULL)) {
        /* r = q * m */
        if (wc_ecc_mulmod(m, q, r, a, prime, 1) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_mulmod qm error");
            ret = 0;
        }
    }
    /* No values to use. */
    else if (ret == 1) {
        /* Set result to infinity as no values passed in. */
        mp_zero(r->x);
        mp_zero(r->y);
        mp_zero(r->z);
    }

    mp_clear(a);
    mp_clear(prime);
    WC_FREE_VAR_EX(a, NULL, DYNAMIC_TYPE_BIGINT);
    WC_FREE_VAR_EX(prime, NULL, DYNAMIC_TYPE_BIGINT);
    return ret;
}

/* Sum the scalar multiplications of the base point and n, and q and m.
 *
 * r = base point * n + q * m
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in]  group  EC group.
 * @param [out] r      EC point that is result of operation.
 * @param [in]  n      Scalar to multiply by base point. May be NULL.
 * @param [in]  q      EC point to be scalar multiplied. May be NULL.
 * @param [in]  m      Scalar to multiply q by. May be NULL.
 * @param [in]  ctx    Context to use for BN operations. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_EC_POINT_mul(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
    const WOLFSSL_BIGNUM *n, const WOLFSSL_EC_POINT *q, const WOLFSSL_BIGNUM *m,
    WOLFSSL_BN_CTX *ctx)
{
    int ret = 1;

    /* No BN operations performed. */
    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_mul");

    /* Validate parameters. */
    if ((group == NULL) || (r == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_mul NULL error");
        ret = 0;
    }

    /* Ensure the internal representation of the EC point q is setup. */
    if ((ret == 1) && (q != NULL) && (ec_point_setup(q) != 1)) {
        WOLFSSL_MSG("ec_point_setup error");
        ret = 0;
    }

#ifdef DEBUG_WOLFSSL
    if (ret == 1) {
        int nid = wolfSSL_EC_GROUP_get_curve_name(group);
        const char* curve = wolfSSL_OBJ_nid2ln(nid);
        const char* nistName = wolfSSL_EC_curve_nid2nist(nid);
        char* num;
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_mul input q", q);
        num = wolfSSL_BN_bn2hex(n);
        WOLFSSL_MSG_EX("\tn = %s", num);
        XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
        num = wolfSSL_BN_bn2hex(m);
        WOLFSSL_MSG_EX("\tm = %s", num);
        XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
        if (curve != NULL)
            WOLFSSL_MSG_EX("curve name: %s", curve);
        if (nistName != NULL)
            WOLFSSL_MSG_EX("nist curve name: %s", nistName);
    }
#endif

    if (ret == 1) {
        mp_int* ni = (n != NULL) ? (mp_int*)n->internal : NULL;
        ecc_point* qi = (q != NULL) ? (ecc_point*)q->internal : NULL;
        mp_int* mi = (m != NULL) ? (mp_int*)m->internal : NULL;

        /* Perform multiplication with wolfCrypt objects. */
        ret = wolfssl_ec_point_mul(group->curve_idx, (ecc_point*)r->internal,
            ni, qi, mi);
    }

    /* Only on success is the internal point guaranteed to be set. */
    if (r != NULL) {
        r->inSet = (ret == 1);
    }
    /* Copy internal EC point values out to external EC point. */
    if ((ret == 1) && (ec_point_external_set(r) != 1)) {
        WOLFSSL_MSG("ec_point_external_set error");
        ret = 0;
    }

#ifdef DEBUG_WOLFSSL
    if (ret == 1) {
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_mul result", r);
    }
#endif

    return ret;
}
#endif /* !WOLFSSL_ATECC508A && !WOLFSSL_ATECC608A && !HAVE_SELFTEST &&
        * !WOLFSSL_SP_MATH */

/* Invert the point on the curve.
 * (x, y) -> (x, -y) = (x, (prime - y) % prime)
 *
 * @param [in]      curveIdx  Index of curve in ecc_set.
 * @param [in, out] point     EC point to invert.
 * @return  1 on success.
 * @return  0 on error.
 */
static int wolfssl_ec_point_invert(int curveIdx, ecc_point* point)
{
    int ret = 1;
    WC_DECLARE_VAR(prime, mp_int, 1, 0);

    /* Allocate memory for an MP int to hold the prime of the curve. */
    WC_ALLOC_VAR_EX(prime, mp_int, 1, NULL, DYNAMIC_TYPE_BIGINT, ret=0);

    /* Initialize MP int. */
    if ((ret == 1) && (mp_init(prime) != MP_OKAY)) {
        WOLFSSL_MSG("mp_init_multi error");
        ret = 0;
    }

    /* Read the curve parameter: prime. */
    if ((ret == 1) && (mp_read_radix(prime, ecc_sets[curveIdx].prime,
            MP_RADIX_HEX) != MP_OKAY)) {
        WOLFSSL_MSG("mp_read_radix prime error");
        ret = 0;
    }

    /* y = (prime - y) mod prime. */
    if ((ret == 1) && (!mp_iszero(point->y)) && (mp_sub(prime, point->y,
            point->y) != MP_OKAY)) {
        WOLFSSL_MSG("mp_sub error");
        ret = 0;
    }

    /* Dispose of memory associated with MP. */
    mp_free(prime);
    WC_FREE_VAR_EX(prime, NULL, DYNAMIC_TYPE_BIGINT);
    return ret;
}

/* Invert the point on the curve.
 * (x, y) -> (x, -y) = (x, (prime - y) % prime)
 *
 * @param [in]      group  EC group.
 * @param [in, out] point  EC point to invert.
 * @param [in]      ctx    Context to use for BN operations. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_EC_POINT_invert(const WOLFSSL_EC_GROUP *group,
    WOLFSSL_EC_POINT *point, WOLFSSL_BN_CTX *ctx)
{
    int ret = 1;

    /* No BN operations performed. */
    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_invert");

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL) || (point->internal == NULL)) {
        ret = 0;
    }

    /* Ensure internal representation of point is setup. */
    if ((ret == 1) && (ec_point_setup(point) != 1)) {
        ret = 0;
    }

#ifdef DEBUG_WOLFSSL
    if (ret == 1) {
        int nid = wolfSSL_EC_GROUP_get_curve_name(group);
        const char* curve = wolfSSL_OBJ_nid2ln(nid);
        const char* nistName = wolfSSL_EC_curve_nid2nist(nid);
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_invert input", point);
        if (curve != NULL)
            WOLFSSL_MSG_EX("curve name: %s", curve);
        if (nistName != NULL)
            WOLFSSL_MSG_EX("nist curve name: %s", nistName);

    }
#endif

    if (ret == 1 && !wolfSSL_BN_is_one(point->Z)) {
#if !defined(WOLFSSL_SP_MATH) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)
        if (ec_point_convert_to_affine(group, point) != 0)
            ret = 0;
#else
        WOLFSSL_MSG("wolfSSL_EC_POINT_invert called on non-affine point");
        ret = 0;
#endif
    }

    if (ret == 1) {
        /* Perform inversion using wolfCrypt objects. */
        ret = wolfssl_ec_point_invert(group->curve_idx,
            (ecc_point*)point->internal);
    }

    /* Set the external EC point representation based on internal. */
    if ((ret == 1) && (ec_point_external_set(point) != 1)) {
        WOLFSSL_MSG("ec_point_external_set error");
        ret = 0;
    }

#ifdef DEBUG_WOLFSSL
    if (ret == 1) {
        wolfSSL_EC_POINT_dump("wolfSSL_EC_POINT_invert result", point);
    }
#endif

    return ret;
}

#ifdef WOLFSSL_EC_POINT_CMP_JACOBIAN
/* Compare two points on a the same curve.
 *
 * (Ax, Ay, Az) => (Ax / (Az ^ 2), Ay / (Az ^ 3))
 * (Bx, By, Bz) => (Bx / (Bz ^ 2), By / (Bz ^ 3))
 * When equal:
 *      (Ax / (Az ^ 2), Ay / (Az ^ 3)) = (Bx / (Bz ^ 2), By / (Bz ^ 3))
 *   => (Ax * (Bz ^ 2), Ay * (Bz ^ 3)) = (Bx * (Az ^ 2), By * (Az ^ 3))
 *
 * @param [in] group  EC group.
 * @param [in] a      EC point to compare.
 * @param [in] b      EC point to compare.
 * @return  0 when equal.
 * @return  1 when different.
 * @return  -1 on error.
 */
static int ec_point_cmp_jacobian(const WOLFSSL_EC_GROUP* group,
    const WOLFSSL_EC_POINT *a, const WOLFSSL_EC_POINT *b, WOLFSSL_BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM* at = BN_new();
    BIGNUM* bt = BN_new();
    BIGNUM* az = BN_new();
    BIGNUM* bz = BN_new();
    BIGNUM* mod = BN_new();

    /* Check that the big numbers were allocated. */
    if ((at == NULL) || (bt == NULL) || (az == NULL) || (bz == NULL) ||
            (mod == NULL)) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    /* Get the modulus for the curve. */
    if ((ret == 0) &&
            (BN_hex2bn(&mod, ecc_sets[group->curve_idx].prime) != 1)) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    if (ret == 0) {
        /* bt = Bx * (Az ^ 2). When Az is one then just copy. */
        if (BN_is_one(a->Z)) {
            if (BN_copy(bt, b->X) == NULL) {
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
        /* az = Az ^ 2 */
        else if ((BN_mod_mul(az, a->Z, a->Z, mod, ctx) != 1)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* bt = Bx * az = Bx * (Az ^ 2) */
        else if (BN_mod_mul(bt, b->X, az, mod, ctx) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 0) {
        /* at = Ax * (Bz ^ 2). When Bz is one then just copy. */
        if (BN_is_one(b->Z)) {
            if (BN_copy(at, a->X) == NULL) {
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
        /* bz = Bz ^ 2 */
        else if (BN_mod_mul(bz, b->Z, b->Z, mod, ctx) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* at = Ax * bz = Ax * (Bz ^ 2) */
        else if (BN_mod_mul(at, a->X, bz, mod, ctx) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    /* Compare x-ordinates. */
    if ((ret == 0) && (BN_cmp(at, bt) != 0)) {
        ret = 1;
    }
    if (ret == 0) {
        /* bt = By * (Az ^ 3). When Az is one then just copy. */
        if (BN_is_one(a->Z)) {
            if (BN_copy(bt, b->Y) == NULL) {
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
        /* az = az * Az = Az ^ 3 */
        else if ((BN_mod_mul(az, az, a->Z, mod, ctx) != 1)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* bt = By * az = By * (Az ^ 3) */
        else if (BN_mod_mul(bt, b->Y, az, mod, ctx) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 0) {
        /* at = Ay * (Bz ^ 3). When Bz is one then just copy. */
        if (BN_is_one(b->Z)) {
            if (BN_copy(at, a->Y) == NULL) {
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
        /* bz = bz * Bz = Bz ^ 3 */
        else if (BN_mod_mul(bz, bz, b->Z, mod, ctx) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* at = Ay * bz = Ay * (Bz ^ 3) */
        else if (BN_mod_mul(at, a->Y, bz, mod, ctx) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    /* Compare y-ordinates. */
    if ((ret == 0) && (BN_cmp(at, bt) != 0)) {
        ret = 1;
    }

    BN_free(mod);
    BN_free(bz);
    BN_free(az);
    BN_free(bt);
    BN_free(at);
    return ret;
}
#endif

/* Compare two points on a the same curve.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] group  EC group.
 * @param [in] a      EC point to compare.
 * @param [in] b      EC point to compare.
 * @param [in] ctx    Context to use for BN operations. Unused.
 * @return  0 when equal.
 * @return  1 when different.
 * @return  -1 on error.
 */
int wolfSSL_EC_POINT_cmp(const WOLFSSL_EC_GROUP *group,
    const WOLFSSL_EC_POINT *a, const WOLFSSL_EC_POINT *b, WOLFSSL_BN_CTX *ctx)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_cmp");

    /* Validate parameters. */
    if ((group == NULL) || (a == NULL) || (a->internal == NULL) ||
            (b == NULL) || (b->internal == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_cmp Bad arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }
    if (ret != -1) {
    #ifdef WOLFSSL_EC_POINT_CMP_JACOBIAN
        /* If same Z ordinate then no need to convert to affine. */
        if (BN_cmp(a->Z, b->Z) == 0) {
            /* Compare */
            ret = ((BN_cmp(a->X, b->X) != 0) || (BN_cmp(a->Y, b->Y) != 0));
        }
        else {
            ret = ec_point_cmp_jacobian(group, a, b, ctx);
        }
    #else
        /* No BN operations performed. */
        (void)ctx;

        ret = (wc_ecc_cmp_point((ecc_point*)a->internal,
            (ecc_point*)b->internal) != MP_EQ);
    #endif
    }

    return ret;
}

/* Copy EC point.
 *
 * @param [out] dest  EC point to copy into.
 * @param [in]  src   EC point to copy.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_EC_POINT_copy(WOLFSSL_EC_POINT *dest, const WOLFSSL_EC_POINT *src)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_copy");

    /* Validate parameters. */
    if ((dest == NULL) || (src == NULL)) {
        ret = 0;
    }

    /* Ensure internal EC point of src is setup. */
    if ((ret == 1) && (ec_point_setup(src) != 1)) {
        ret = 0;
    }

    /* Copy internal EC points. */
    if ((ret == 1) && (wc_ecc_copy_point((ecc_point*)src->internal,
            (ecc_point*)dest->internal) != MP_OKAY)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Destinatation internal point is set. */
        dest->inSet = 1;

        /* Set the external EC point of dest based on internal. */
        if (ec_point_external_set(dest) != 1) {
            ret = 0;
        }
    }

    return ret;
}

/* Checks whether point is at infinity.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] group  EC group.
 * @param [in] point  EC point to check.
 * @return  1 when at infinity.
 * @return  0 when not at infinity.
 */
int wolfSSL_EC_POINT_is_at_infinity(const WOLFSSL_EC_GROUP *group,
    const WOLFSSL_EC_POINT *point)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_is_at_infinity");

    /* Validate parameters. */
    if ((group == NULL) || (point == NULL) || (point->internal == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_is_at_infinity NULL error");
        ret = 0;
    }

    /* Ensure internal EC point is setup. */
    if ((ret == 1) && (ec_point_setup(point) != 1)) {
        ret = 0;
    }
    if (ret == 1) {
    #ifndef WOLF_CRYPTO_CB_ONLY_ECC
        /* Check for infinity. */
        ret = wc_ecc_point_is_at_infinity((ecc_point*)point->internal);
        if (ret < 0) {
            WOLFSSL_MSG("ecc_point_is_at_infinity failure");
            /* Error return is 0 by OpenSSL. */
            ret = 0;
        }
    #else
        WOLFSSL_MSG("ecc_point_is_at_infinitiy compiled out");
        ret = 0;
    #endif
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

/* End EC_POINT */

/* Start EC_KEY */

#ifdef OPENSSL_EXTRA

/*
 * EC key constructor/deconstructor APIs
 */

/* Allocate a new EC key.
 *
 * Not OpenSSL API.
 *
 * @param [in] heap   Heap hint for dynamic memory allocation.
 * @param [in] devId  Device identifier value.
 * @return  New, allocated EC key on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_ex(void* heap, int devId)
{
    WOLFSSL_EC_KEY *key = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_new");

    /* Allocate memory for EC key. */
    key = (WOLFSSL_EC_KEY*)XMALLOC(sizeof(WOLFSSL_EC_KEY), heap,
        DYNAMIC_TYPE_ECC);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new malloc WOLFSSL_EC_KEY failure");
        err = 1;
    }
    if (!err) {
        /* Reset all fields to 0. */
        XMEMSET(key, 0, sizeof(WOLFSSL_EC_KEY));
        /* Cache heap hint. */
        key->heap = heap;
        /* Initialize fields to defaults. */
        key->form     = WC_POINT_CONVERSION_UNCOMPRESSED;

        /* Initialize reference count. */
        wolfSSL_RefInit(&key->ref, &err);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    }
    if (!err) {
#endif
        /* Allocate memory for internal EC key representation. */
        key->internal = (ecc_key*)XMALLOC(sizeof(ecc_key), heap,
            DYNAMIC_TYPE_ECC);
        if (key->internal == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_new malloc ecc key failure");
            err = 1;
        }
    }
    if (!err) {
        /* Initialize wolfCrypt EC key. */
        if (wc_ecc_init_ex((ecc_key*)key->internal, heap, devId) != 0) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_new init ecc key failure");
            err = 1;
        }
    }

    if (!err) {
        /* Group unknown at creation */
        key->group = wolfSSL_EC_GROUP_new_by_curve_name(WC_NID_undef);
        if (key->group == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_new malloc WOLFSSL_EC_GROUP failure");
            err = 1;
        }
    }

    if (!err) {
        /* Allocate a point as public key. */
        key->pub_key = wolfSSL_EC_POINT_new(key->group);
        if (key->pub_key == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_new failure");
            err = 1;
        }
    }

    if (!err) {
        /* Allocate a BN as private key. */
        key->priv_key = wolfSSL_BN_new();
        if (key->priv_key == NULL) {
            WOLFSSL_MSG("wolfSSL_BN_new failure");
            err = 1;
        }
    }

    if (err) {
        /* Dispose of EC key on error. */
        wolfSSL_EC_KEY_free(key);
        key = NULL;
    }
    /* Return new EC key object. */
    return key;
}

/* Allocate a new EC key.
 *
 * @return  New, allocated EC key on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new(void)
{
    return wolfSSL_EC_KEY_new_ex(NULL, INVALID_DEVID);
}

/* Create new EC key with the group having the specified numeric ID.
 *
 * @param [in] nid  Numeric ID.
 * @return  New, allocated EC key on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_by_curve_name(int nid)
{
    WOLFSSL_EC_KEY *key;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_new_by_curve_name");

    /* Allocate empty, EC key. */
    key = wolfSSL_EC_KEY_new();
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new failure");
        err = 1;
    }

    if (!err) {
        /* Set group to be nid. */
        ec_group_set_nid(key->group, nid);
        if (key->group->curve_idx == -1) {
            wolfSSL_EC_KEY_free(key);
            key = NULL;
        }
    }

    /* Return the new EC key object. */
    return key;
}

/* Dispose of the EC key and allocated data.
 *
 * Cannot use key after this call.
 *
 * @param [in] key  EC key to free.
 */
void wolfSSL_EC_KEY_free(WOLFSSL_EC_KEY *key)
{
    int doFree = 0;
    int err;

    (void)err;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_free");

    if (key != NULL) {
        void* heap = key->heap;

        /* Decrement reference count. */
        wolfSSL_RefDec(&key->ref, &doFree, &err);
        if (doFree) {
            /* Dispose of allocated reference counting data. */
            wolfSSL_RefFree(&key->ref);

            /* Dispose of private key. */
            wolfSSL_BN_free(key->priv_key);
            wolfSSL_EC_POINT_free(key->pub_key);
            wolfSSL_EC_GROUP_free(key->group);
            if (key->internal != NULL) {
                /* Dispose of wolfCrypt representation of EC key. */
                wc_ecc_free((ecc_key*)key->internal);
                XFREE(key->internal, heap, DYNAMIC_TYPE_ECC);
            }

            /* Set back to NULLs for safety. */
            ForceZero(key, sizeof(*key));

            /* Dispose of the memory associated with the EC key. */
            XFREE(key, heap, DYNAMIC_TYPE_ECC);
            (void)heap;
        }
    }
}

/* Increments ref count of EC key.
 *
 * @param [in, out] key  EC key.
 * @return  1 on success
 * @return  0 on error
 */
int wolfSSL_EC_KEY_up_ref(WOLFSSL_EC_KEY* key)
{
    int err = 1;

    if (key != NULL) {
        wolfSSL_RefInc(&key->ref, &err);
    }

    return !err;
}

#ifndef NO_CERTS

#if defined(OPENSSL_ALL)
/* Copy the internal, wolfCrypt EC key.
 *
 * @param [in, out] dst  Destination wolfCrypt EC key.
 * @param [in]      src  Source wolfCrypt EC key.
 * @return  0 on success.
 * @return  Negative on error.
 */
static int wolfssl_ec_key_int_copy(ecc_key* dst, const ecc_key* src)
{
    int ret;

    /* Copy public key. */
#if !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
    ret = wc_ecc_copy_point(&src->pubkey, &dst->pubkey);
#else
    ret = wc_ecc_copy_point((ecc_point*)&src->pubkey, &dst->pubkey);
#endif
    if (ret != MP_OKAY) {
        WOLFSSL_MSG("wc_ecc_copy_point error");
    }

    if (ret == 0) {
        /* Copy private key. */
        ret = mp_copy(wc_ecc_key_get_priv((ecc_key*)src),
            wc_ecc_key_get_priv(dst));
        if (ret != MP_OKAY) {
            WOLFSSL_MSG("mp_copy error");
        }
    }

    if (ret == 0) {
        /* Copy domain parameters. */
        if (src->dp) {
            ret = wc_ecc_set_curve(dst, 0, src->dp->id);
            if (ret != 0) {
                WOLFSSL_MSG("wc_ecc_set_curve error");
            }
        }
    }

    if (ret == 0) {
        /* Copy the other components. */
        dst->type  = src->type;
        dst->idx   = src->idx;
        dst->state = src->state;
        dst->flags = src->flags;
    }

    return ret;
}

/* Copies ecc_key into new WOLFSSL_EC_KEY object
 *
 * Copies the internal representation as well.
 *
 * @param [in] src  EC key to duplicate.
 *
 * @return  EC key on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_dup(const WOLFSSL_EC_KEY *src)
{
    int err = 0;
    WOLFSSL_EC_KEY* newKey = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_dup");

    /* Validate EC key. */
    if ((src == NULL) || (src->internal == NULL) || (src->group == NULL) ||
         (src->pub_key == NULL) || (src->priv_key == NULL)) {
        WOLFSSL_MSG("src NULL error");
        err = 1;
    }

    if (!err) {
        /* Create a new, empty key. */
        newKey = wolfSSL_EC_KEY_new();
        if (newKey == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_new error");
            err = 1;
        }
    }

    if (!err) {
        /* Copy internal EC key. */
        if (wolfssl_ec_key_int_copy((ecc_key*)newKey->internal,
                (ecc_key*)src->internal) != 0) {
            WOLFSSL_MSG("Copying internal EC key error");
            err = 1;
        }
    }
    if (!err) {
        /* Internal key set. */
        newKey->inSet = 1;

        /* Copy group */
        err = wolfssl_ec_group_copy(newKey->group, src->group);
    }
    /* Copy public key. */
    if ((!err) && (wolfSSL_EC_POINT_copy(newKey->pub_key, src->pub_key) != 1)) {
        WOLFSSL_MSG("Copying EC public key error");
        err = 1;
    }

    if (!err) {
        /* Set header size of private key in PKCS#8 format.*/
        newKey->pkcs8HeaderSz = src->pkcs8HeaderSz;

        /* Copy private key. */
        if (wolfSSL_BN_copy(newKey->priv_key, src->priv_key) == NULL) {
            WOLFSSL_MSG("Copying EC private key error");
            err = 1;
        }
    }

    if (err) {
        /* Dispose of EC key on error. */
        wolfSSL_EC_KEY_free(newKey);
        newKey = NULL;
    }
    /* Return the new EC key. */
    return newKey;
}

#endif /* OPENSSL_ALL */

#endif /* !NO_CERTS */

/*
 * EC key to/from bin/octet APIs
 */

/* Create an EC key from the octet encoded public key.
 *
 * Behaviour checked against OpenSSL.
 *
 * @param [out]     key  Reference to EC key. Must pass in a valid object with
 *                       group set.
 * @param [in, out] in   On in, reference to buffer that contains data.
 *                       On out, reference to buffer after public key data.
 * @param [in]      len  Length of data in the buffer. Must be length of the
 *                       encoded public key.
 * @return  Allocated EC key on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY *wolfSSL_o2i_ECPublicKey(WOLFSSL_EC_KEY **key,
   const unsigned char **in, long len)
{
    int err = 0;
    WOLFSSL_EC_KEY* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_o2i_ECPublicKey");

    /* Validate parameters: EC group needed to perform import. */
    if ((key == NULL) || (*key == NULL) || ((*key)->group == NULL) ||
            (in == NULL) || (*in == NULL) || (len <= 0)) {
        WOLFSSL_MSG("wolfSSL_o2i_ECPublicKey Bad arguments");
        err = 1;
    }

    if (!err) {
        /* Return the EC key object passed in. */
        ret = *key;

        /* Import point into public key field. */
        if (wolfSSL_EC_POINT_oct2point(ret->group, ret->pub_key, *in,
                (size_t)len, NULL) != 1) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_oct2point error");
            ret = NULL;
            err = 1;
        }
    }
    if (!err) {
        /* Assumed length passed in is all the data. */
        *in += len;
    }

    return ret;
}

/* Puts the encoded public key into out.
 *
 * Passing in NULL for out returns length only.
 * Passing in NULL for *out has buffer allocated, encoded into and passed back.
 * Passing non-NULL for *out has it encoded into and pointer moved past.
 *
 * @param [in]      key  EC key to encode.
 * @param [in, out] out  Reference to buffer to encode into. May be NULL or
 *                       point to NULL.
 * @return  Length of encoding in bytes on success.
 * @return  0 on error.
 */
int wolfSSL_i2o_ECPublicKey(const WOLFSSL_EC_KEY *key, unsigned char **out)
{
    int ret = 1;
    size_t len = 0;
    int form = WC_POINT_CONVERSION_UNCOMPRESSED;

    WOLFSSL_ENTER("wolfSSL_i2o_ECPublicKey");

    /* Validate parameters. */
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_i2o_ECPublicKey Bad arguments");
        ret = 0;
    }

    /* Ensure the external key data is set from the internal EC key. */
    if ((ret == 1) && (!key->exSet) && (SetECKeyExternal((WOLFSSL_EC_KEY*)
            key) != 1)) {
        WOLFSSL_MSG("SetECKeyExternal failure");
        ret = 0;
    }

    if (ret == 1) {
    #ifdef HAVE_COMP_KEY
        /* Default to compressed form if not set */
        form = (key->form == WC_POINT_CONVERSION_UNCOMPRESSED) ?
               WC_POINT_CONVERSION_UNCOMPRESSED :
               WC_POINT_CONVERSION_COMPRESSED;
    #endif

        /* Calculate length of point encoding. */
        len = wolfSSL_EC_POINT_point2oct(key->group, key->pub_key, form, NULL,
            0, NULL);
    }
    /* Encode if length calculated and pointer supplied to update. */
    if ((ret == 1) && (len != 0) && (out != NULL)) {
        unsigned char *tmp = NULL;

        /* Allocate buffer for encoding if no buffer supplied. */
        if (*out == NULL) {
            tmp = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_OPENSSL);
            if (tmp == NULL) {
                WOLFSSL_MSG("malloc failed");
                ret = 0;
            }
        }
        else {
            /* Get buffer to encode into. */
            tmp = *out;
        }

        /* Encode public key into buffer. */
        if ((ret == 1) && (wolfSSL_EC_POINT_point2oct(key->group, key->pub_key,
                form, tmp, len, NULL) == 0)) {
            ret = 0;
        }

        if (ret == 1) {
            /* Return buffer if allocated. */
            if (*out == NULL) {
                *out = tmp;
            }
            else {
                /* Step over encoded data if not allocated. */
                *out += len;
            }
        }
        else if (*out == NULL) {
            /* Dispose of allocated buffer. */
            XFREE(tmp, NULL, DYNAMIC_TYPE_OPENSSL);
        }
    }

    if (ret == 1) {
        /* Return length on success. */
        ret = (int)len;
    }
    return ret;
}

#ifdef HAVE_ECC_KEY_IMPORT
/* Create a EC key from the DER encoded private key.
 *
 * @param [out]     key   Reference to EC key.
 * @param [in, out] in    On in, reference to buffer that contains DER data.
 *                        On out, reference to buffer after private key data.
 * @param [in]      long  Length of data in the buffer. May be larger than the
 *                        length of the encoded private key.
 * @return  Allocated EC key on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY* wolfSSL_d2i_ECPrivateKey(WOLFSSL_EC_KEY** key,
    const unsigned char** in, long len)
{
    int err = 0;
    word32 idx = 0;
    WOLFSSL_EC_KEY* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_ECPrivateKey");

    /* Validate parameters. */
    if ((in == NULL) || (*in == NULL) || (len <= 0)) {
        WOLFSSL_MSG("wolfSSL_d2i_ECPrivateKey Bad arguments");
        err = 1;
    }

    /* Create a new, empty EC key.  */
    if ((!err) && ((ret = wolfSSL_EC_KEY_new()) == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new error");
        err = 1;
    }

    /* Decode the private key DER data into internal EC key. */
    if ((!err) && (wc_EccPrivateKeyDecode(*in, &idx, (ecc_key*)ret->internal,
            (word32)len) != 0)) {
        WOLFSSL_MSG("wc_EccPrivateKeyDecode error");
        err = 1;
    }

    if (!err) {
        /* Internal EC key setup. */
        ret->inSet = 1;

        /* Set the EC key from the internal values. */
        if (SetECKeyExternal(ret) != 1) {
            WOLFSSL_MSG("SetECKeyExternal error");
            err = 1;
        }
    }

    if (!err) {
        /* Move buffer on to next byte after data used. */
        *in += idx;
        if (key) {
            /* Return new EC key through reference. */
            *key = ret;
        }
    }

    if (err && (ret != NULL)) {
        /* Dispose of allocated EC key. */
        wolfSSL_EC_KEY_free(ret);
        ret = NULL;
    }
    return ret;
}
#endif /* HAVE_ECC_KEY_IMPORT */

/* Enecode the private key of the EC key into the buffer as DER.
 *
 * @param [in]      key  EC key to encode.
 * @param [in, out] out  On in, reference to buffer to place DER encoding into.
 *                       On out, reference to buffer after the encoding.
 *                       May be NULL.
 * @return  Length of DER encoding on success.
 * @return  0 on error.
 */
int wolfSSL_i2d_ECPrivateKey(const WOLFSSL_EC_KEY *key, unsigned char **out)
{
    int err = 0;
    word32 len = 0;

    WOLFSSL_ENTER("wolfSSL_i2d_ECPrivateKey");

    /* Validate parameters. */
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_i2d_ECPrivateKey Bad arguments");
        err = 1;
    }

    /* Update the internal EC key if not set. */
    if ((!err) && (!key->inSet) && (SetECKeyInternal((WOLFSSL_EC_KEY*)key) !=
            1)) {
        WOLFSSL_MSG("SetECKeyInternal error");
        err = 1;
    }

    /* Calculate the length of the private key DER encoding using internal EC
     * key. */
    if ((!err) && ((int)(len = (word32)wc_EccKeyDerSize((ecc_key*)key->internal,
           0)) <= 0)) {
        WOLFSSL_MSG("wc_EccKeyDerSize error");
        err = 1;
    }

    /* Only return length when out is NULL. */
    if ((!err) && (out != NULL)) {
        unsigned char* buf = NULL;

        /* Must have a buffer to encode into. */
        if (*out == NULL) {
            /* Allocate a new buffer of appropriate length. */
            buf = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (buf == NULL) {
                /* Error and return 0. */
                err = 1;
                len = 0;
            }
            else {
                /* Return the allocated buffer. */
                *out = buf;
            }
        }
        /* Encode the internal EC key as a private key in DER format. */
        if ((!err) && wc_EccPrivateKeyToDer((ecc_key*)key->internal, *out,
                len) < 0) {
            WOLFSSL_MSG("wc_EccPrivateKeyToDer error");
            err = 1;
        }
        else if (buf != *out) {
            /* Move the reference to byte past encoded private key. */
            *out += len;
        }

        /* Dispose of any allocated buffer on error. */
        if (err && (*out == buf)) {
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *out = NULL;
        }
    }

    return (int)len;
}

/* Load private key into EC key from DER encoding.
 *
 * Not an OpenSSL compatibility API.
 *
 * @param [in, out] key     EC key to put private key values into.
 * @param [in]      derBuf  Buffer holding DER encoding.
 * @param [in]      derSz   Size of DER encoding in bytes.
 * @return  1 on success.
 * @return  -1 on error.
 */
int wolfSSL_EC_KEY_LoadDer(WOLFSSL_EC_KEY* key, const unsigned char* derBuf,
                           int derSz)
{
    return wolfSSL_EC_KEY_LoadDer_ex(key, derBuf, derSz,
        WOLFSSL_EC_KEY_LOAD_PRIVATE);
}

/* Load private/public key into EC key from DER encoding.
 *
 * Not an OpenSSL compatibility API.
 *
 * @param [in, out] key     EC key to put private/public key values into.
 * @param [in]      derBuf  Buffer holding DER encoding.
 * @param [in]      derSz   Size of DER encoding in bytes.
 * @param [in]      opt     Key type option. Valid values:
 *                            WOLFSSL_EC_KEY_LOAD_PRIVATE,
 *                            WOLFSSL_EC_KEY_LOAD_PUBLIC.
 * @return  1 on success.
 * @return  -1 on error.
 */
int wolfSSL_EC_KEY_LoadDer_ex(WOLFSSL_EC_KEY* key, const unsigned char* derBuf,
                              int derSz, int opt)
{
    int res = 1;
    int ret;
    word32 idx = 0;
    word32 algId;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_LoadDer");

    /* Validate parameters. */
    if ((key == NULL) || (key->internal == NULL) || (derBuf == NULL) ||
            (derSz <= 0)) {
        WOLFSSL_MSG("Bad function arguments");
        res = WOLFSSL_FATAL_ERROR;
    }
    if ((res == 1) && (opt != WOLFSSL_EC_KEY_LOAD_PRIVATE) &&
            (opt != WOLFSSL_EC_KEY_LOAD_PUBLIC)) {
        res = WOLFSSL_FATAL_ERROR;
    }

    if (res == 1) {
        /* Assume no PKCS#8 header. */
        key->pkcs8HeaderSz = 0;

        /* Check if input buffer has PKCS8 header. In the case that it does not
         * have a PKCS8 header then do not error out.
         */
        if ((ret = ToTraditionalInline_ex((const byte*)derBuf, &idx,
                (word32)derSz, &algId)) > 0) {
            WOLFSSL_MSG("Found PKCS8 header");
            key->pkcs8HeaderSz = (word16)idx;
            res = 1;
        }
        /* Error out on parsing error. */
        else if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WOLFSSL_MSG("Unexpected error with trying to remove PKCS8 header");
            res = WOLFSSL_FATAL_ERROR;
        }
    }

    if (res == 1) {
        /* Load into internal EC key based on key type option. */
        if (opt == WOLFSSL_EC_KEY_LOAD_PRIVATE) {
            ret = wc_EccPrivateKeyDecode(derBuf, &idx, (ecc_key*)key->internal,
                (word32)derSz);
        }
        else {
            ret = wc_EccPublicKeyDecode(derBuf, &idx, (ecc_key*)key->internal,
                (word32)derSz);
            if (ret < 0) {
                ecc_key *tmp = (ecc_key*)XMALLOC(sizeof(ecc_key),
                    ((ecc_key*)key->internal)->heap, DYNAMIC_TYPE_ECC);
                if (tmp == NULL) {
                    ret = WOLFSSL_FATAL_ERROR;
                }
                else {
                    /* We now try again as x.963 [point type][x][opt y]. */
                    ret = wc_ecc_init_ex(tmp, ((ecc_key*)key->internal)->heap,
                                         INVALID_DEVID);
                    if (ret == 0) {
                        ret = wc_ecc_import_x963(derBuf, (word32)derSz, tmp);
                        if (ret == 0) {
                            /* Take ownership of new key - set tmp to the old
                             * key which will then be freed below. */
                            ecc_key *old = (ecc_key *)key->internal;
                            key->internal = tmp;
                            tmp = old;

                            idx = (word32)derSz;
                        }
                        wc_ecc_free(tmp);
                    }
                    XFREE(tmp, ((ecc_key*)key->internal)->heap,
                          DYNAMIC_TYPE_ECC);
                }
            }
        }
        if (ret < 0) {
            /* Error returned from wolfSSL. */
            if (opt == WOLFSSL_EC_KEY_LOAD_PRIVATE) {
                WOLFSSL_MSG("wc_EccPrivateKeyDecode failed");
            }
            else {
                WOLFSSL_MSG("wc_EccPublicKeyDecode failed");
            }
            res = WOLFSSL_FATAL_ERROR;
        }

        /* Internal key updated - update whether it is a valid key. */
        key->inSet = (res == 1);
    }

    /* Set the external EC key based on value in internal. */
    if ((res == 1) && (SetECKeyExternal(key) != 1)) {
        WOLFSSL_MSG("SetECKeyExternal failed");
        res = WOLFSSL_FATAL_ERROR;
    }

    return res;
}


#ifndef NO_BIO

WOLFSSL_EC_KEY *wolfSSL_d2i_EC_PUBKEY_bio(WOLFSSL_BIO *bio,
        WOLFSSL_EC_KEY **out)
{
    char* data = NULL;
    int dataSz = 0;
    int memAlloced = 0;
    WOLFSSL_EC_KEY* ec = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_EC_PUBKEY_bio");

    if (bio == NULL)
        return NULL;

    if (err == 0 && wolfssl_read_bio(bio, &data, &dataSz, &memAlloced) != 0) {
        WOLFSSL_ERROR_MSG("wolfssl_read_bio failed");
        err = 1;
    }

    if (err == 0 && (ec = wolfSSL_EC_KEY_new()) == NULL) {
        WOLFSSL_ERROR_MSG("wolfSSL_EC_KEY_new failed");
        err = 1;
    }

    /* Load the EC key with the public key from the DER encoding. */
    if (err == 0 && wolfSSL_EC_KEY_LoadDer_ex(ec, (const unsigned char*)data,
            dataSz, WOLFSSL_EC_KEY_LOAD_PUBLIC) != 1) {
        WOLFSSL_ERROR_MSG("wolfSSL_EC_KEY_LoadDer_ex failed");
        err = 1;
    }

    if (memAlloced)
        XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (err) { /* on error */
        wolfSSL_EC_KEY_free(ec);
        ec = NULL;
    }
    else { /* on success */
        if (out != NULL)
            *out = ec;
    }

    return ec;
}

#endif /* !NO_BIO */

/*
 * EC key PEM APIs
 */

#ifdef HAVE_ECC_KEY_EXPORT
#if defined(WOLFSSL_KEY_GEN) && (!defined(NO_FILESYSTEM) || !defined(NO_BIO))
/* Encode the EC public key as DER.
 *
 * @param [in]  key   EC key to encode.
 * @param [out] der   Pointer through which buffer is returned.
 * @param [in]  heap  Heap hint.
 * @return  Size of encoding on success.
 * @return  0 on error.
 */
static int wolfssl_ec_key_to_pubkey_der(WOLFSSL_EC_KEY* key,
    unsigned char** der, void* heap)
{
    int sz;
    unsigned char* buf = NULL;

    (void)heap;

    /* Calculate encoded size to allocate. */
    sz = wc_EccPublicKeyDerSize((ecc_key*)key->internal, 1);
    if (sz <= 0) {
        WOLFSSL_MSG("wc_EccPublicKeyDerSize failed");
        sz = 0;
    }
    if (sz > 0) {
        /* Allocate memory to hold encoding. */
        buf = (byte*)XMALLOC((size_t)sz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL) {
            WOLFSSL_MSG("malloc failed");
            sz = 0;
        }
    }
    if (sz > 0) {
        /* Encode public key to DER using wolfSSL.  */
        sz = wc_EccPublicKeyToDer((ecc_key*)key->internal, buf, (word32)sz, 1);
        if (sz < 0) {
            WOLFSSL_MSG("wc_EccPublicKeyToDer failed");
            sz = 0;
        }
    }

    /* Return buffer on success. */
    if (sz > 0) {
        *der = buf;
    }
    else {
        /* Dispose of any dynamically allocated data not returned. */
        XFREE(buf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return sz;
}
#endif

#if !defined(NO_FILESYSTEM) && defined(WOLFSSL_KEY_GEN)
/*
 * Return code compliant with OpenSSL.
 *
 * @param [in] fp   File pointer to write PEM encoding to.
 * @param [in] key  EC key to encode and write.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_PEM_write_EC_PUBKEY(XFILE fp, WOLFSSL_EC_KEY* key)
{
    int ret = 1;
    unsigned char* derBuf = NULL;
    int derSz = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_write_EC_PUBKEY");

    /* Validate parameters. */
    if ((fp == XBADFILE) || (key == NULL)) {
        WOLFSSL_MSG("Bad argument.");
        return 0;
    }

    /* Encode public key in EC key as DER. */
    derSz = wolfssl_ec_key_to_pubkey_der(key, &derBuf, key->heap);
    if (derSz == 0) {
        ret = 0;
    }

    /* Write out to file the PEM encoding of the DER. */
    if ((ret == 1) && (der_write_to_file_as_pem(derBuf, derSz, fp,
            ECC_PUBLICKEY_TYPE, key->heap) != 1)) {
        ret = 0;
    }

    /* Dispose of any dynamically allocated data. */
    XFREE(derBuf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    WOLFSSL_LEAVE("wolfSSL_PEM_write_EC_PUBKEY", ret);

    return ret;
}
#endif
#endif

#ifndef NO_BIO
/* Read a PEM encoded EC public key from a BIO.
 *
 * @param [in]  bio   BIO to read EC public key from.
 * @param [out] out   Pointer to return EC key object through. May be NULL.
 * @param [in]  cb    Password callback when PEM encrypted.
 * @param [in]  pass  NUL terminated string for passphrase when PEM
 *                    encrypted.
 * @return  New EC key object on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY* wolfSSL_PEM_read_bio_EC_PUBKEY(WOLFSSL_BIO* bio,
    WOLFSSL_EC_KEY** out, wc_pem_password_cb* cb, void *pass)
{
    int             err = 0;
    WOLFSSL_EC_KEY* ec = NULL;
    DerBuffer*      der = NULL;
    int             keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_EC_PUBKEY");

    /* Validate parameters. */
    if (bio == NULL) {
        err = 1;
    }

    if (!err) {
        /* Create an empty EC key. */
        ec = wolfSSL_EC_KEY_new();
        if (ec == NULL) {
            err = 1;
        }
    }
    /* Read a PEM key in to a new DER buffer. */
    if ((!err) && (pem_read_bio_key(bio, cb, pass, ECC_PUBLICKEY_TYPE,
            &keyFormat, &der) <= 0)) {
        err = 1;
    }
    /* Load the EC key with the public key from the DER encoding. */
    if ((!err) && (wolfSSL_EC_KEY_LoadDer_ex(ec, der->buffer, (int)der->length,
            WOLFSSL_EC_KEY_LOAD_PUBLIC) != 1)) {
        WOLFSSL_ERROR_MSG("Error loading DER buffer into WOLFSSL_EC_KEY");
        err = 1;
    }

    /* Dispose of dynamically allocated data not needed anymore. */
    FreeDer(&der);
    if (err) {
        wolfSSL_EC_KEY_free(ec);
        ec = NULL;
    }

    /* Return EC key through out if required. */
    if ((out != NULL) && (ec != NULL)) {
        *out = ec;
    }
    return ec;
}

/* Read a PEM encoded EC private key from a BIO.
 *
 * @param [in]  bio   BIO to read EC private key from.
 * @param [out] out   Pointer to return EC key object through. May be NULL.
 * @param [in]  cb    Password callback when PEM encrypted.
 * @param [in]  pass  NUL terminated string for passphrase when PEM
 *                    encrypted.
 * @return  New EC key object on success.
 * @return  NULL on error.
 */
WOLFSSL_EC_KEY* wolfSSL_PEM_read_bio_ECPrivateKey(WOLFSSL_BIO* bio,
   WOLFSSL_EC_KEY** out, wc_pem_password_cb* cb, void *pass)
{
    int             err = 0;
    WOLFSSL_EC_KEY* ec = NULL;
    DerBuffer*      der = NULL;
    int             keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_ECPrivateKey");

    /* Validate parameters. */
    if (bio == NULL) {
        err = 1;
    }

    if (!err) {
        /* Create an empty EC key. */
        ec = wolfSSL_EC_KEY_new();
        if (ec == NULL) {
            err = 1;
        }
    }
    /* Read a PEM key in to a new DER buffer.
     * To check ENC EC PRIVATE KEY, it uses PRIVATEKEY_TYPE to call
     * pem_read_bio_key(), and then check key format if it is EC.
     */
    if ((!err) && (pem_read_bio_key(bio, cb, pass, PRIVATEKEY_TYPE,
            &keyFormat, &der) <= 0)) {
        err = 1;
    }
    if (keyFormat != ECDSAk) {
        WOLFSSL_ERROR_MSG("Error not EC key format");
        err = 1;
    }
    /* Load the EC key with the private key from the DER encoding. */
    if ((!err) && (wolfSSL_EC_KEY_LoadDer_ex(ec, der->buffer, (int)der->length,
            WOLFSSL_EC_KEY_LOAD_PRIVATE) != 1)) {
        WOLFSSL_ERROR_MSG("Error loading DER buffer into WOLFSSL_EC_KEY");
        err = 1;
    }

    /* Dispose of dynamically allocated data not needed anymore. */
    FreeDer(&der);
    if (err) {
        wolfSSL_EC_KEY_free(ec);
        ec = NULL;
    }

    /* Return EC key through out if required. */
    if ((out != NULL) && (ec != NULL)) {
        *out = ec;
    }
    return ec;
}
#endif /* !NO_BIO */

#if defined(WOLFSSL_KEY_GEN) && defined(HAVE_ECC_KEY_EXPORT)
#ifndef NO_BIO
/* Write out the EC public key as PEM to the BIO.
 *
 * @param [in] bio  BIO to write PEM encoding to.
 * @param [in] ec   EC public key to encode.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_PEM_write_bio_EC_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_EC_KEY* ec)
{
    int ret = 1;
    unsigned char* derBuf = NULL;
    int derSz = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_EC_PUBKEY");

    /* Validate parameters. */
    if ((bio == NULL) || (ec == NULL)) {
        WOLFSSL_MSG("Bad Function Arguments");
        return 0;
    }

    /* Encode public key in EC key as DER. */
    derSz = wolfssl_ec_key_to_pubkey_der(ec, &derBuf, ec->heap);
    if (derSz == 0) {
        ret = 0;
    }

    /* Write out to BIO the PEM encoding of the EC public key. */
    if ((ret == 1) && (der_write_to_bio_as_pem(derBuf, derSz, bio,
            ECC_PUBLICKEY_TYPE) != 1)) {
        ret = 0;
    }

    /* Dispose of any dynamically allocated data. */
    XFREE(derBuf, ec->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* Write out the EC private key as PEM to the BIO.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] bio       BIO to write PEM encoding to.
 * @param [in] ec        EC private key to encode.
 * @param [in] cipher    Cipher to use when PEM encrypted. May be NULL.
 * @param [in] passwd    Password string when PEM encrypted. May be NULL.
 * @param [in] passwdSz  Length of password string when PEM encrypted.
 * @param [in] cb        Password callback when PEM encrypted. Unused.
 * @param [in] pass      NUL terminated string for passphrase when PEM
 *                       encrypted. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_PEM_write_bio_ECPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_EC_KEY* ec,
    const WOLFSSL_EVP_CIPHER* cipher, unsigned char* passwd, int passwdSz,
    wc_pem_password_cb* cb, void* arg)
{
    int ret = 1;
    unsigned char* pem = NULL;
    int pLen = 0;

    (void)cb;
    (void)arg;

    /* Validate parameters. */
    if ((bio == NULL) || (ec == NULL)) {
        ret = 0;
    }

    /* Write EC private key to PEM. */
    if ((ret == 1) && (wolfSSL_PEM_write_mem_ECPrivateKey(ec, cipher, passwd,
            passwdSz, &pem, &pLen) != 1)) {
       ret = 0;
    }
    /* Write PEM to BIO. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, pem, pLen) != pLen)) {
        WOLFSSL_ERROR_MSG("EC private key BIO write failed");
        ret = 0;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}

#endif /* !NO_BIO */

/* Encode the EC private key as PEM into buffer.
 *
 * Return code compliant with OpenSSL.
 * Not an OpenSSL API.
 *
 * @param [in]  ec        EC private key to encode.
 * @param [in]  cipher    Cipher to use when PEM encrypted. May be NULL.
 * @param [in]  passwd    Password string when PEM encrypted. May be NULL.
 * @param [in]  passwdSz  Length of password string when PEM encrypted.
 * @param [out] pem       Newly allocated buffer holding PEM encoding.
 * @param [out] pLen      Length of PEM encoding in bytes.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_PEM_write_mem_ECPrivateKey(WOLFSSL_EC_KEY* ec,
    const WOLFSSL_EVP_CIPHER* cipher, unsigned char* passwd, int passwdSz,
    unsigned char **pem, int *pLen)
{
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    int ret = 1;
    byte* derBuf = NULL;
    word32 der_max_len = 0;
    int derSz = 0;

    WOLFSSL_MSG("wolfSSL_PEM_write_mem_ECPrivateKey");

    /* Validate parameters. */
    if ((pem == NULL) || (pLen == NULL) || (ec == NULL) ||
            (ec->internal == NULL)) {
        WOLFSSL_MSG("Bad function arguments");
        ret = 0;
    }

    /* Ensure internal EC key is set from external. */
    if ((ret == 1) && (ec->inSet == 0)) {
        WOLFSSL_MSG("No ECC internal set, do it");

        if (SetECKeyInternal(ec) != 1) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Calculate maximum size of DER encoding.
         * 4 > size of pub, priv + ASN.1 additional information */
        der_max_len = 4 * (word32)wc_ecc_size((ecc_key*)ec->internal) +
                      WC_AES_BLOCK_SIZE;

        /* Allocate buffer big enough to hold encoding. */
        derBuf = (byte*)XMALLOC((size_t)der_max_len, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (derBuf == NULL) {
            WOLFSSL_MSG("malloc failed");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Encode EC private key as DER. */
        derSz = wc_EccKeyToDer((ecc_key*)ec->internal, derBuf, der_max_len);
        if (derSz < 0) {
            WOLFSSL_MSG("wc_EccKeyToDer failed");
            XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
            ret = 0;
        }
    }

    /* Convert DER to PEM - possibly encrypting. */
    if ((ret == 1) && (der_to_enc_pem_alloc(derBuf, derSz, cipher, passwd,
            passwdSz, ECC_PRIVATEKEY_TYPE, NULL, pem, pLen) != 1)) {
        WOLFSSL_ERROR_MSG("der_to_enc_pem_alloc failed");
        ret = 0;
    }

    return ret;
#else
    (void)ec;
    (void)cipher;
    (void)passwd;
    (void)passwdSz;
    (void)pem;
    (void)pLen;
    return 0;
#endif /* WOLFSSL_PEM_TO_DER || WOLFSSL_DER_TO_PEM */
}

#ifndef NO_FILESYSTEM
/* Write out the EC private key as PEM to file.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] fp        File pointer to write PEM encoding to.
 * @param [in] ec        EC private key to encode.
 * @param [in] cipher    Cipher to use when PEM encrypted. May be NULL.
 * @param [in] passwd    Password string when PEM encrypted. May be NULL.
 * @param [in] passwdSz  Length of password string when PEM encrypted.
 * @param [in] cb        Password callback when PEM encrypted. Unused.
 * @param [in] pass      NUL terminated string for passphrase when PEM
 *                       encrypted. Unused.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_PEM_write_ECPrivateKey(XFILE fp, WOLFSSL_EC_KEY *ec,
    const WOLFSSL_EVP_CIPHER *cipher, unsigned char *passwd, int passwdSz,
    wc_pem_password_cb *cb, void *pass)
{
    int ret = 1;
    byte *pem = NULL;
    int pLen = 0;

    (void)cb;
    (void)pass;

    WOLFSSL_MSG("wolfSSL_PEM_write_ECPrivateKey");

    /* Validate parameters. */
    if ((fp == XBADFILE) || (ec == NULL) || (ec->internal == NULL)) {
        WOLFSSL_MSG("Bad function arguments");
        ret = 0;
    }

    /* Write EC private key to PEM. */
    if ((ret == 1) && (wolfSSL_PEM_write_mem_ECPrivateKey(ec, cipher, passwd,
            passwdSz, &pem, &pLen) != 1)) {
        WOLFSSL_MSG("wolfSSL_PEM_write_mem_ECPrivateKey failed");
        ret = 0;
    }

    /* Write out to file the PEM encoding of the EC private key. */
    if ((ret == 1) && ((int)XFWRITE(pem, 1, (size_t)pLen, fp) != pLen)) {
        WOLFSSL_MSG("ECC private key file write failed");
        ret = 0;
    }

    /* Dispose of any dynamically allocated data. */
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);

    return ret;
}

#endif /* NO_FILESYSTEM */
#endif /* WOLFSSL_KEY_GEN && HAVE_ECC_KEY_EXPORT */

/*
 * EC key print APIs
 */

#ifndef NO_CERTS

#if defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
/* Print the EC key to a file pointer as text.
 *
 * @param [in] fp      File pointer.
 * @param [in] key     EC key to print.
 * @param [in] indent  Number of spaces to place before each line printed.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_EC_KEY_print_fp(XFILE fp, WOLFSSL_EC_KEY* key, int indent)
{
    int ret = 1;
    int bits = 0;
    int priv = 0;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_print_fp");

    /* Validate parameters. */
    if ((fp == XBADFILE) || (key == NULL) || (key->group == NULL) ||
            (indent < 0)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Get EC groups order size in bits. */
        bits = wolfSSL_EC_GROUP_order_bits(key->group);
        if (bits <= 0) {
            WOLFSSL_MSG("Failed to get group order bits.");
            ret = 0;
        }
    }
    if (ret == 1) {
        const char* keyType;

        /* Determine whether this is a private or public key. */
        if ((key->priv_key != NULL) && (!wolfSSL_BN_is_zero(key->priv_key))) {
            keyType = "Private-Key";
            priv = 1;
        }
        else {
            keyType = "Public-Key";
        }

        /* Print key header. */
        if (XFPRINTF(fp, "%*s%s: (%d bit)\n", indent, "", keyType, bits) < 0) {
            ret = 0;
        }
    }
    if ((ret == 1) && priv) {
        /* Print the private key BN. */
        ret = pk_bn_field_print_fp(fp, indent, "priv", key->priv_key);
    }
    /* Check for public key data in EC key. */
    if ((ret == 1) && (key->pub_key != NULL) && (key->pub_key->exSet)) {
        /* Get the public key point as one BN. */
        WOLFSSL_BIGNUM* pubBn = wolfSSL_EC_POINT_point2bn(key->group,
            key->pub_key, WC_POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
        if (pubBn == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_point2bn failed.");
            ret = 0;
        }
        else {
            /* Print the public key in a BN. */
            ret = pk_bn_field_print_fp(fp, indent, "pub", pubBn);
            wolfSSL_BN_free(pubBn);
        }
    }
    if (ret == 1) {
        /* Get the NID of the group. */
        int nid = wolfSSL_EC_GROUP_get_curve_name(key->group);
        if (nid > 0) {
            /* Convert the NID into a long name and NIST name. */
            const char* curve = wolfSSL_OBJ_nid2ln(nid);
            const char* nistName = wolfSSL_EC_curve_nid2nist(nid);

            /* Print OID name if known. */
            if ((curve != NULL) &&
                (XFPRINTF(fp, "%*sASN1 OID: %s\n", indent, "", curve) < 0)) {
                ret = 0;
            }
            /* Print NIST curve name if known. */
            if ((nistName != NULL) &&
                (XFPRINTF(fp, "%*sNIST CURVE: %s\n", indent, "",
                    nistName) < 0)) {
                ret = 0;
            }
        }
    }


    WOLFSSL_LEAVE("wolfSSL_EC_KEY_print_fp", ret);

    return ret;
}
#endif /* XFPRINTF && !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */

#endif /* !NO_CERTS */

/*
 * EC_KEY get/set/test APIs
 */

/* Set data of internal, wolfCrypt EC key object into EC key.
 *
 * EC_KEY wolfSSL -> OpenSSL
 *
 * @param [in, out] p  EC key to update.
 * @return  1 on success.
 * @return  -1 on failure.
 */
int SetECKeyExternal(WOLFSSL_EC_KEY* eckey)
{
    int ret = 1;

    WOLFSSL_ENTER("SetECKeyExternal");

    /* Validate parameter. */
    if ((eckey == NULL) || (eckey->internal == NULL)) {
        WOLFSSL_MSG("ec key NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        ecc_key* key = (ecc_key*)eckey->internal;

        /* Set group (OID, nid and idx) from wolfCrypt EC key. */
        eckey->group->curve_oid = (int)key->dp->oidSum;
        eckey->group->curve_nid = EccEnumToNID(key->dp->id);
        eckey->group->curve_idx = key->idx;

        if (eckey->pub_key->internal != NULL) {
            /* Copy internal public point from internal key's public point. */
            if (wc_ecc_copy_point(&key->pubkey,
                    (ecc_point*)eckey->pub_key->internal) != MP_OKAY) {
                WOLFSSL_MSG("SetECKeyExternal ecc_copy_point failed");
                ret = WOLFSSL_FATAL_ERROR;
            }

            /* Set external public key from internal wolfCrypt, public key. */
            if ((ret == 1) && (ec_point_external_set(eckey->pub_key) != 1)) {
                WOLFSSL_MSG("SetECKeyExternal ec_point_external_set failed");
                ret = WOLFSSL_FATAL_ERROR;
            }
        }

        /* set the external privkey */
        if ((ret == 1) && (key->type == ECC_PRIVATEKEY) &&
                (wolfssl_bn_set_value(&eckey->priv_key,
                wc_ecc_key_get_priv(key)) != 1)) {
            WOLFSSL_MSG("ec priv key error");
            ret = WOLFSSL_FATAL_ERROR;
        }

        /* External values set when operations succeeded. */
        eckey->exSet = (ret == 1);
    }

    return ret;
}

/* Set data of EC key into internal, wolfCrypt EC key object.
 *
 * EC_KEY Openssl -> WolfSSL
 *
 * @param [in, out] p  EC key to update.
 * @return  1 on success.
 * @return  -1 on failure.
 */
int SetECKeyInternal(WOLFSSL_EC_KEY* eckey)
{
    int ret = 1;

    WOLFSSL_ENTER("SetECKeyInternal");

    /* Validate parameter. */
    if ((eckey == NULL) || (eckey->internal == NULL) ||
            (eckey->group == NULL)) {
        WOLFSSL_MSG("ec key NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        ecc_key* key = (ecc_key*)eckey->internal;
        int pubSet = 0;

        /* Validate group. */
        if ((eckey->group->curve_idx < 0) ||
            (wc_ecc_is_valid_idx(eckey->group->curve_idx) == 0)) {
            WOLFSSL_MSG("invalid curve idx");
            ret = WOLFSSL_FATAL_ERROR;
        }

        if (ret == 1) {
            /* Set group (idx of curve and corresponding domain parameters). */
            key->idx = eckey->group->curve_idx;
            key->dp = &ecc_sets[key->idx];
            pubSet = (eckey->pub_key != NULL);
        }
        /* Set public key (point). */
        if ((ret == 1) && pubSet) {
            if (ec_point_internal_set(eckey->pub_key) != 1) {
                WOLFSSL_MSG("ec key pub error");
                ret = WOLFSSL_FATAL_ERROR;
            }
            /* Copy public point to key. */
            if ((ret == 1) && (wc_ecc_copy_point(
                    (ecc_point*)eckey->pub_key->internal, &key->pubkey) !=
                    MP_OKAY)) {
                WOLFSSL_MSG("wc_ecc_copy_point error");
                ret = WOLFSSL_FATAL_ERROR;
            }

            if (ret == 1) {
                /* Set that the internal key is a public key */
                key->type = ECC_PUBLICKEY;
            }
        }

        /* set privkey */
        if ((ret == 1) && (eckey->priv_key != NULL)) {
            if (wolfssl_bn_get_value(eckey->priv_key,
                    wc_ecc_key_get_priv(key)) != 1) {
                WOLFSSL_MSG("ec key priv error");
                ret = WOLFSSL_FATAL_ERROR;
            }
            /* private key */
            if ((ret == 1) && (!mp_iszero(wc_ecc_key_get_priv(key)))) {
                if (pubSet) {
                    key->type = ECC_PRIVATEKEY;
                }
                else {
                    key->type = ECC_PRIVATEKEY_ONLY;
                }
            }
        }

        /* Internal values set when operations succeeded. */
        eckey->inSet = (ret == 1);
    }

    return ret;
}

/* Get point conversion format of EC key.
 *
 * @param [in] key  EC key.
 * @return  Point conversion format on success.
 * @return  -1 on error.
 */
wc_point_conversion_form_t wolfSSL_EC_KEY_get_conv_form(
    const WOLFSSL_EC_KEY* key)
{
    if (key == NULL)
        return WOLFSSL_FATAL_ERROR;
    return key->form;
}

/* Set point conversion format into EC key.
 *
 * @param [in, out] key   EC key to set format into.
 * @param [in]      form  Point conversion format. Valid values:
 *                          WC_POINT_CONVERSION_UNCOMPRESSED,
 *                          WC_POINT_CONVERSION_COMPRESSED (when HAVE_COMP_KEY)
 */
void wolfSSL_EC_KEY_set_conv_form(WOLFSSL_EC_KEY *key, int form)
{
    if (key == NULL) {
        WOLFSSL_MSG("Key passed in NULL");
    }
    else if (form == WC_POINT_CONVERSION_UNCOMPRESSED
#ifdef HAVE_COMP_KEY
          || form == WC_POINT_CONVERSION_COMPRESSED
#endif
             ) {
        key->form = (unsigned char)form;
    }
    else {
        WOLFSSL_MSG("Incorrect form or HAVE_COMP_KEY not compiled in");
    }
}

/* Get the EC group object that is in EC key.
 *
 * @param [in] key  EC key.
 * @return  EC group object on success.
 * @return  NULL when key is NULL.
 */
const WOLFSSL_EC_GROUP *wolfSSL_EC_KEY_get0_group(const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_EC_GROUP* group = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_get0_group");

    if (key != NULL) {
        group = key->group;
    }

    return group;
}

/* Set the group in WOLFSSL_EC_KEY
 *
 * @param [in, out] key    EC key to update.
 * @param [in]      group  EC group to copy.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC_KEY_set_group(WOLFSSL_EC_KEY *key, WOLFSSL_EC_GROUP *group)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_group");

    /* Validate parameters. */
    if ((key == NULL) || (group == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Dispose of the current group. */
        if (key->group != NULL) {
            wolfSSL_EC_GROUP_free(key->group);
        }
        /* Duplicate the passed in group into EC key. */
        key->group = wolfSSL_EC_GROUP_dup(group);
        if (key->group == NULL) {
            ret = 0;
        }
    }

    return ret;
}

/* Get the BN object that is the private key in the EC key.
 *
 * @param [in] key  EC key.
 * @return  BN object on success.
 * @return  NULL when key is NULL or private key is not set.
 */
WOLFSSL_BIGNUM *wolfSSL_EC_KEY_get0_private_key(const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_BIGNUM* priv_key = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_get0_private_key");

    /* Validate parameter. */
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_get0_private_key Bad arguments");
    }
    /* Only return private key if it is not 0. */
    else if (!wolfSSL_BN_is_zero(key->priv_key)) {
        priv_key = key->priv_key;
    }

    return priv_key;
}

/* Sets the private key value into EC key.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in, out] key       EC key to set.
 * @param [in]      priv_key  Private key value in a BN.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC_KEY_set_private_key(WOLFSSL_EC_KEY *key,
    const WOLFSSL_BIGNUM *priv_key)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_private_key");

    /* Validate parameters. */
    if ((key == NULL) || (priv_key == NULL)) {
        WOLFSSL_MSG("Bad arguments");
        ret = 0;
    }

    /* Check for obvious invalid values. */
    if (wolfSSL_BN_is_negative(priv_key) || wolfSSL_BN_is_zero(priv_key) ||
            wolfSSL_BN_is_one(priv_key)) {
        WOLFSSL_MSG("Invalid private key value");
        ret = 0;
    }

    if (ret == 1) {
        /* Free key if previously set. */
        if (key->priv_key != NULL) {
            wolfSSL_BN_free(key->priv_key);
        }

        /* Duplicate the BN passed in. */
        key->priv_key = wolfSSL_BN_dup(priv_key);
        if (key->priv_key == NULL) {
            WOLFSSL_MSG("key ecc priv key NULL");
            ret = 0;
        }
    }
    /* Set the external values into internal EC key. */
    if ((ret == 1) && (SetECKeyInternal(key) != 1)) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        /* Dispose of new private key on error. */
        wolfSSL_BN_free(key->priv_key);
        key->priv_key = NULL;
        ret = 0;
    }

    return ret;
}

/* Get the public key EC point object that is in EC key.
 *
 * @param [in] key  EC key.
 * @return  EC point object that is the public key on success.
 * @return  NULL when key is NULL.
 */
WOLFSSL_EC_POINT* wolfSSL_EC_KEY_get0_public_key(const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_EC_POINT* pub_key = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_get0_public_key");

    if (key != NULL) {
        pub_key = key->pub_key;
    }

    return pub_key;
}

/*
 * Return code compliant with OpenSSL.
 *
 * @param [in, out] key  EC key.
 * @param [in]      pub  Public key as an EC point.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC_KEY_set_public_key(WOLFSSL_EC_KEY *key,
    const WOLFSSL_EC_POINT *pub)
{
    int ret = 1;
    ecc_point *pub_p = NULL;
    ecc_point *key_p = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_public_key");

    /* Validate parameters. */
    if ((key == NULL) || (key->internal == NULL) || (pub == NULL) ||
            (pub->internal == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_set_public_key Bad arguments");
        ret = 0;
    }

    /* Ensure the internal EC key is set. */
    if ((ret == 1) && (key->inSet == 0) && (SetECKeyInternal(key) != 1)) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        ret = 0;
    }

    /* Ensure the internal EC point of pub is setup. */
    if ((ret == 1) && (ec_point_setup(pub) != 1)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Get the internal point of pub and the public key in key. */
        pub_p = (ecc_point*)pub->internal;
        key_p = (ecc_point*)key->pub_key->internal;

        /* Create new point if required. */
        if (key_p == NULL) {
            key_p = wc_ecc_new_point();
            key->pub_key->internal = (void*)key_p;
        }
        /* Check point available. */
        if (key_p == NULL) {
            WOLFSSL_MSG("key ecc point NULL");
            ret = 0;
        }
    }

    /* Copy the internal pub point into internal key point. */
    if ((ret == 1) && (wc_ecc_copy_point(pub_p, key_p) != MP_OKAY)) {
        WOLFSSL_MSG("ecc_copy_point failure");
        ret = 0;
    }

    /* Copy the internal point data into external. */
    if ((ret == 1) && (ec_point_external_set(key->pub_key) != 1)) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        ret = 0;
    }

    /* Copy the internal key into external. */
    if ((ret == 1) && (SetECKeyInternal(key) != 1)) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        ret = 0;
    }

    if (ret == 1) {
        /* Dump out the point and the key's public key for debug. */
        wolfSSL_EC_POINT_dump("pub", pub);
        wolfSSL_EC_POINT_dump("key->pub_key", key->pub_key);
    }

    return ret;
}

#ifndef NO_WOLFSSL_STUB
/* Set the ASN.1 encoding flag against the EC key.
 *
 * No implementation as only named curves supported for encoding.
 *
 * @param [in, out] key   EC key.
 * @param [in]      flag  ASN.1 flag to set. Valid values:
 *                        OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE
 */
void wolfSSL_EC_KEY_set_asn1_flag(WOLFSSL_EC_KEY *key, int asn1_flag)
{
    (void)key;
    (void)asn1_flag;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_asn1_flag");
    WOLFSSL_STUB("EC_KEY_set_asn1_flag");
}
#endif

/*
 * EC key generate key APIs
 */

/* Generate an EC key.
 *
 * Uses the internal curve index set in the EC key or the default.
 *
 * @param [in, out] key  EC key.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC_KEY_generate_key(WOLFSSL_EC_KEY *key)
{
    int res = 1;
    int initTmpRng = 0;
    WC_RNG* rng = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);

    WOLFSSL_ENTER("wolfSSL_EC_KEY_generate_key");

    /* Validate parameters. */
    if ((key == NULL) || (key->internal == NULL) || (key->group == NULL)) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key Bad arguments");
        res = 0;
    }
    if (res == 1) {
        /* Check if we know which internal curve index to use. */
        if (key->group->curve_idx < 0) {
            /* Generate key using the default curve. */
#if FIPS_VERSION3_GE(6,0,0)
            key->group->curve_idx = ECC_SECP256R1; /* FIPS default to 256 */
#else
            key->group->curve_idx = ECC_CURVE_DEF;
#endif
        }

        /* Create a random number generator. */
        rng = wolfssl_make_rng(tmpRng, &initTmpRng);
        if (rng == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key failed to make RNG");
            res = 0;
        }
    }
    if (res == 1) {
        /* NIDToEccEnum returns -1 for invalid NID so if key->group->curve_nid
         * is 0 then pass ECC_CURVE_DEF as arg */
        int eccEnum = key->group->curve_nid ?
#if FIPS_VERSION3_GE(6,0,0)
            NIDToEccEnum(key->group->curve_nid) : ECC_SECP256R1;
#else
            NIDToEccEnum(key->group->curve_nid) : ECC_CURVE_DEF;
#endif
        /* Get the internal EC key. */
        ecc_key* ecKey = (ecc_key*)key->internal;
        /* Make the key using internal API. */
        int ret = 0;

#if FIPS_VERSION3_GE(6,0,0)
        /* In the case of FIPS only allow key generation with approved curves */
        if (eccEnum != ECC_SECP256R1 && eccEnum != ECC_SECP224R1 &&
            eccEnum != ECC_SECP384R1 && eccEnum != ECC_SECP521R1) {
            WOLFSSL_MSG("Unsupported curve selected in FIPS mode");
            res = 0;
        }
        if (res == 1) {
#endif
        ret  = wc_ecc_make_key_ex(rng, 0, ecKey, eccEnum);
#if FIPS_VERSION3_GE(6,0,0)
        }
#endif

    #if defined(WOLFSSL_ASYNC_CRYPT)
        /* Wait on asynchronouse operation. */
        ret = wc_AsyncWait(ret, &ecKey->asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret != 0) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key wc_ecc_make_key failed");
            res = 0;
        }
    }

    /* Dispose of local random number generator if initialized. */
    if (initTmpRng) {
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_RNG);
    }

    /* Set the external key from new internal key values. */
    if ((res == 1) && (SetECKeyExternal(key) != 1)) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key SetECKeyExternal failed");
        res = 0;
    }

    return res;
}

/*
 * EC key check key APIs
 */

/* Check that the EC key is valid.
 *
 * @param [in] key  EC key.
 * @return  1 on valid.
 * @return  0 on invalid or error.
 */
int wolfSSL_EC_KEY_check_key(const WOLFSSL_EC_KEY *key)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_check_key");

    /* Validate parameter. */
    if ((key == NULL) || (key->internal == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }

    /* Set the external EC key values into internal if not already. */
    if ((ret == 1) && (key->inSet == 0) && (SetECKeyInternal(
            (WOLFSSL_EC_KEY*)key) != 1)) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        ret = 0;
    }

    if (ret == 1) {
        /* Have internal EC implementation check key. */
        ret = wc_ecc_check_key((ecc_key*)key->internal) == 0;
    }

    return ret;
}

/* End EC_KEY */

#if !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
/* Get the supported, built-in EC curves
 *
 * @param [in, out] curves  Pre-allocated list to put supported curves into.
 * @param [in]      len     Maximum number of items to place in list.
 * @return  Number of built-in EC curves when curves is NULL or len is 0.
 * @return  Number of items placed in list otherwise.
 */
size_t wolfSSL_EC_get_builtin_curves(WOLFSSL_EC_BUILTIN_CURVE *curves,
    size_t len)
{
    size_t i;
    size_t cnt;
#ifdef HAVE_SELFTEST
    /* Defined in ecc.h when available. */
    size_t ecc_sets_count;

    /* Count the pre-defined curves since global not available. */
    for (i = 0; ecc_sets[i].size != 0 && ecc_sets[i].name != NULL; i++) {
        /* Do nothing. */
    }
    ecc_sets_count = i;
#endif

    /* Assume we are going to return total count. */
    cnt = ecc_sets_count;
    /* Check we have a list that can hold data. */
    if ((curves != NULL) && (len != 0)) {
        /* Limit count to length of list. */
        if (cnt > len) {
            cnt = len;
        }

        /* Put in built-in EC curve nid and short name. */
        for (i = 0; i < cnt; i++) {
            curves[i].nid = EccEnumToNID(ecc_sets[i].id);
            curves[i].comment = wolfSSL_OBJ_nid2sn(curves[i].nid);
        }
    }

    return cnt;
}
#endif /* !HAVE_FIPS || FIPS_VERSION_GT(2,0) */

/* Start ECDSA_SIG */

/* Allocate a new ECDSA signature object.
 *
 * @return  New, allocated ECDSA signature object on success.
 * @return  NULL on error.
 */
WOLFSSL_ECDSA_SIG *wolfSSL_ECDSA_SIG_new(void)
{
    int err = 0;
    WOLFSSL_ECDSA_SIG *sig;

    WOLFSSL_ENTER("wolfSSL_ECDSA_SIG_new");

    /* Allocate memory for ECDSA signature object. */
    sig = (WOLFSSL_ECDSA_SIG*)XMALLOC(sizeof(WOLFSSL_ECDSA_SIG), NULL,
        DYNAMIC_TYPE_ECC);
    if (sig == NULL) {
        WOLFSSL_MSG("wolfSSL_ECDSA_SIG_new malloc ECDSA signature failure");
        err = 1;
    }

    if (!err) {
        /* Set s to NULL in case of error. */
        sig->s = NULL;
        /* Allocate BN into r. */
        sig->r = wolfSSL_BN_new();
        if (sig->r == NULL) {
            WOLFSSL_MSG("wolfSSL_ECDSA_SIG_new malloc ECDSA r failure");
            err = 1;
        }
    }
    if (!err) {
        /* Allocate BN into s. */
        sig->s = wolfSSL_BN_new();
        if (sig->s == NULL) {
            WOLFSSL_MSG("wolfSSL_ECDSA_SIG_new malloc ECDSA s failure");
            err = 1;
        }
    }

    if (err && (sig != NULL)) {
        /* Dispose of allocated memory. */
        wolfSSL_ECDSA_SIG_free(sig);
        sig = NULL;
    }
    return sig;
}

/* Dispose of ECDSA signature object.
 *
 * Cannot use object after this call.
 *
 * @param [in] sig  ECDSA signature object to free.
 */
void wolfSSL_ECDSA_SIG_free(WOLFSSL_ECDSA_SIG *sig)
{
    WOLFSSL_ENTER("wolfSSL_ECDSA_SIG_free");

    if (sig != NULL) {
        /* Dispose of BNs allocated for r and s. */
        wolfSSL_BN_free(sig->r);
        wolfSSL_BN_free(sig->s);

        /* Dispose of memory associated with ECDSA signature object. */
        XFREE(sig, NULL, DYNAMIC_TYPE_ECC);
    }
}

/* Create an ECDSA signature from the DER encoding.
 *
 * @param [in, out] sig  Reference to ECDSA signature object. May be NULL.
 * @param [in, out] pp   On in, reference to buffer containing DER encoding.
 *                       On out, reference to buffer after signature data.
 * @param [in]      len  Length of the data in the buffer. May be more than
 *                       the length of the signature.
 * @return  ECDSA signature object on success.
 * @return  NULL on error.
 */
WOLFSSL_ECDSA_SIG* wolfSSL_d2i_ECDSA_SIG(WOLFSSL_ECDSA_SIG** sig,
    const unsigned char** pp, long len)
{
    int err = 0;
    /* ECDSA signature object to return. */
    WOLFSSL_ECDSA_SIG *s = NULL;

    /* Validate parameter. */
    if (pp == NULL) {
        err = 1;
    }
    if (!err) {
        if (sig != NULL) {
            /* Use the ECDSA signature object passed in. */
            s = *sig;
        }
        if (s == NULL) {
            /* No ECDSA signature object passed in - create a new one. */
            s = wolfSSL_ECDSA_SIG_new();
            if (s == NULL) {
                err = 1;
            }
        }
    }
    if (!err) {
        /* DecodeECC_DSA_Sig calls mp_init, so free these. */
        mp_free((mp_int*)s->r->internal);
        mp_free((mp_int*)s->s->internal);

        /* Decode the signature into internal r and s fields. */
        if (DecodeECC_DSA_Sig(*pp, (word32)len, (mp_int*)s->r->internal,
                (mp_int*)s->s->internal) != MP_OKAY) {
            err = 1;
        }
    }

    if (!err) {
        /* Move pointer passed signature data successfully decoded. */
        *pp += wolfssl_der_length(*pp, (int)len);
        if (sig != NULL) {
            /* Update reference to ECDSA signature object. */
            *sig = s;
        }
    }

    /* Dispose of newly allocated object on error. */
    if (err) {
        if ((s != NULL) && ((sig == NULL) || (*sig != s))) {
            wolfSSL_ECDSA_SIG_free(s);
        }
        /* Return NULL for object on error. */
        s = NULL;
    }
    return s;
}

/* Encode the ECDSA signature as DER.
 *
 * @param [in]      sig  ECDSA signature object.
 * @param [in, out] pp   On in, reference to buffer in which to place encoding.
 *                       On out, reference to buffer after encoding.
 *                       May be NULL or point to NULL in which case no encoding
 *                       is done.
 * @return  Length of encoding on success.
 * @return  0 on error.
 */
int wolfSSL_i2d_ECDSA_SIG(const WOLFSSL_ECDSA_SIG *sig, unsigned char **pp)
{
    word32 len = 0;
    int    update_p = 1;

    /* Validate parameter. */
    if (sig != NULL) {
        /* ASN.1: SEQ + INT + INT
         *   ASN.1 Integer must be a positive value - prepend zero if number has
         *   top bit set.
         */
        /* Get total length of r including any prepended zero. */
        word32 rLen = (word32)(mp_leading_bit((mp_int*)sig->r->internal) +
               mp_unsigned_bin_size((mp_int*)sig->r->internal));
        /* Get total length of s including any prepended zero. */
        word32 sLen = (word32)(mp_leading_bit((mp_int*)sig->s->internal) +
               mp_unsigned_bin_size((mp_int*)sig->s->internal));
        /* Calculate length of data in sequence. */
        len = (word32)1 + ASN_LEN_SIZE(rLen) + rLen +
              (word32)1 + ASN_LEN_SIZE(sLen) + sLen;
        /* Add in the length of the SEQUENCE. */
        len += (word32)1 + ASN_LEN_SIZE(len);

        #ifdef WOLFSSL_I2D_ECDSA_SIG_ALLOC
        if ((pp != NULL) && (*pp == NULL)) {
            *pp = (unsigned char *)XMALLOC(len, NULL, DYNAMIC_TYPE_OPENSSL);
            if (*pp != NULL) {
                WOLFSSL_MSG("malloc error");
                return 0;
            }
            update_p = 0;
        }
        #endif

        /* Encode only if there is a buffer to encode into. */
        if ((pp != NULL) && (*pp != NULL)) {
            /* Encode using the internal representations of r and s. */
            if (StoreECC_DSA_Sig(*pp, &len, (mp_int*)sig->r->internal,
                    (mp_int*)sig->s->internal) != MP_OKAY) {
                /* No bytes encoded. */
                len = 0;
            }
            else if (update_p) {
                /* Update pointer to after encoding. */
                *pp += len;
            }
        }
    }

    return (int)len;
}

/* Get the pointer to the fields of the ECDSA signature.
 *
 * r and s untouched when sig is NULL.
 *
 * @param [in]  sig  ECDSA signature object.
 * @param [out] r    R field of ECDSA signature as a BN. May be NULL.
 * @param [out] s    S field of ECDSA signature as a BN. May be NULL.
 */
void wolfSSL_ECDSA_SIG_get0(const WOLFSSL_ECDSA_SIG* sig,
    const WOLFSSL_BIGNUM** r, const WOLFSSL_BIGNUM** s)
{
    /* Validate parameter. */
    if (sig != NULL) {
        /* Return the r BN when pointer to return through. */
        if (r != NULL) {
            *r = sig->r;
        }
        /* Return the s BN when pointer to return through. */
        if (s != NULL) {
            *s = sig->s;
        }
    }
}

/* Set the pointers to the fields of the ECDSA signature.
 *
 * @param [in, out] sig  ECDSA signature object to update.
 * @param [in]      r    R field of ECDSA signature as a BN.
 * @param [in]      s    S field of ECDSA signature as a BN.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_ECDSA_SIG_set0(WOLFSSL_ECDSA_SIG* sig, WOLFSSL_BIGNUM* r,
    WOLFSSL_BIGNUM* s)
{
    int ret = 1;

    /* Validate parameters. */
    if ((sig == NULL) || (r == NULL) || (s == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Dispose of old BN objects. */
        wolfSSL_BN_free(sig->r);
        wolfSSL_BN_free(sig->s);

        /* Assign new BN objects. */
        sig->r = r;
        sig->s = s;
    }

    return ret;
}

/* End ECDSA_SIG */

/* Start ECDSA */

/* Calculate maximum size of the DER encoded ECDSA signature for the curve.
 *
 * @param [in] key  EC key.
 * @return  Size of DER encoded signature on success.
 * @return  0 on error.
 */
int wolfSSL_ECDSA_size(const WOLFSSL_EC_KEY *key)
{
    int err = 0;
    int len = 0;
    const WOLFSSL_EC_GROUP *group = NULL;
    int bits = 0;

    /* Validate parameter. */
    if (key == NULL) {
        err = 1;
    }

    /* Get group from key to get order bits. */
    if ((!err) && ((group = wolfSSL_EC_KEY_get0_group(key)) == NULL)) {
        err = 1;
    }
    /* Get order bits of group. */
    if ((!err) && ((bits = wolfSSL_EC_GROUP_order_bits(group)) == 0)) {
        /* Group is not set. */
        err = 1;
    }

    if (!err) {
        /* r and s are mod order. */
        int bytes = (bits + 7) / 8;  /* Bytes needed to hold bits. */
        len = SIG_HEADER_SZ + /* 2*ASN_TAG + 2*LEN(ENUM) */
            ECC_MAX_PAD_SZ +  /* possible leading zeroes in r and s */
            bytes + bytes;    /* max r and s in bytes */
    }

    return len;
}

/* Create ECDSA signature by signing digest with key.
 *
 * @param [in] dgst  Digest to sign.
 * @param [in] dLen  Length of digest in bytes.
 * @param [in] key   EC key to sign with.
 * @return  ECDSA signature object on success.
 * @return  NULL on error.
 */
WOLFSSL_ECDSA_SIG *wolfSSL_ECDSA_do_sign(const unsigned char *dgst, int dLen,
    WOLFSSL_EC_KEY *key)
{
    int err = 0;
    WOLFSSL_ECDSA_SIG *sig = NULL;
    WC_DECLARE_VAR(out, byte, ECC_BUFSIZE, 0);
    unsigned int outLen = ECC_BUFSIZE;

    WOLFSSL_ENTER("wolfSSL_ECDSA_do_sign");

    /* Validate parameters. */
    if ((dgst == NULL) || (key == NULL) || (key->internal == NULL)) {
        WOLFSSL_MSG("wolfSSL_ECDSA_do_sign Bad arguments");
        err = 1;
    }

    /* Ensure internal EC key is set from external. */
    if ((!err) && (key->inSet == 0)) {
        WOLFSSL_MSG("wolfSSL_ECDSA_do_sign No EC key internal set, do it");

        if (SetECKeyInternal(key) != 1) {
            WOLFSSL_MSG("wolfSSL_ECDSA_do_sign SetECKeyInternal failed");
            err = 1;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (!err) {
        /* Allocate buffer to hold encoded signature. */
        out = (byte*)XMALLOC(outLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (out == NULL) {
            err = 1;
        }
    }
#endif

    /* Sign the digest with the key to create encoded ECDSA signature. */
    if ((!err) && (wolfSSL_ECDSA_sign(0, dgst, dLen, out, &outLen, key) != 1)) {
        err = 1;
    }

    if (!err) {
        const byte* p = out;
        /* Decode the ECDSA signature into a new object. */
        sig = wolfSSL_d2i_ECDSA_SIG(NULL, &p, outLen);
    }

    WC_FREE_VAR_EX(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return sig;
}

/* Verify ECDSA signature in the object using digest and key.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] dgst  Digest to verify.
 * @param [in] dLen  Length of the digest in bytes.
 * @param [in] sig   ECDSA signature object.
 * @param [in] key   EC key containing public key.
 * @return  1 when signature is valid.
 * @return  0 when signature is invalid.
 * @return  -1 on error.
 */
int wolfSSL_ECDSA_do_verify(const unsigned char *dgst, int dLen,
    const WOLFSSL_ECDSA_SIG *sig, WOLFSSL_EC_KEY *key)
{
    int ret = 1;
    int verified = 0;
#ifdef WOLF_CRYPTO_CB_ONLY_ECC
    byte signature[ECC_MAX_SIG_SIZE];
    int signatureLen;
    byte* p = signature;
#endif

    WOLFSSL_ENTER("wolfSSL_ECDSA_do_verify");

    /* Validate parameters. */
    if ((dgst == NULL) || (sig == NULL) || (key == NULL) ||
            (key->internal == NULL)) {
        WOLFSSL_MSG("wolfSSL_ECDSA_do_verify Bad arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }

    /* Ensure internal EC key is set from external. */
    if ((ret == 1) && (key->inSet == 0)) {
        WOLFSSL_MSG("No EC key internal set, do it");

        if (SetECKeyInternal(key) != 1) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 1) {
#ifndef WOLF_CRYPTO_CB_ONLY_ECC
        /* Verify hash using digest, r and s as MP ints and internal EC key. */
        if (wc_ecc_verify_hash_ex((mp_int*)sig->r->internal,
                (mp_int*)sig->s->internal, dgst, (word32)dLen, &verified,
                (ecc_key *)key->internal) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_verify_hash failed");
            ret = WOLFSSL_FATAL_ERROR;
        }
        else if (verified == 0) {
            WOLFSSL_MSG("wc_ecc_verify_hash incorrect signature detected");
            ret = 0;
        }
#else
        signatureLen = i2d_ECDSA_SIG(sig, &p);
        if (signatureLen > 0) {
            /* verify hash. expects to call wc_CryptoCb_EccVerify internally */
            ret = wc_ecc_verify_hash(signature, signatureLen, dgst,
                (word32)dLen, &verified, (ecc_key*)key->internal);
            if (ret != MP_OKAY) {
                WOLFSSL_MSG("wc_ecc_verify_hash failed");
                ret = WOLFSSL_FATAL_ERROR;
            }
            else if (verified == 0) {
                WOLFSSL_MSG("wc_ecc_verify_hash incorrect signature detected");
                ret = 0;
            }
        }
#endif /* WOLF_CRYPTO_CB_ONLY_ECC */
    }

    return ret;
}

/* Sign the digest with the key to produce a DER encode signature.
 *
 * @param [in]      type      Digest algorithm used to create digest. Unused.
 * @param [in]      digest    Digest of the message to sign.
 * @param [in]      digestSz  Size of the digest in bytes.
 * @param [out]     sig       Buffer to hold signature.
 * @param [in, out] sigSz     On in, size of buffer in bytes.
 *                            On out, size of signatre in bytes.
 * @param [in]      key       EC key containing private key.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_ECDSA_sign(int type, const unsigned char *digest, int digestSz,
    unsigned char *sig, unsigned int *sigSz, WOLFSSL_EC_KEY *key)
{
    int ret = 1;
    WC_RNG* rng = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    int initTmpRng = 0;

    WOLFSSL_ENTER("wolfSSL_ECDSA_sign");

    /* Digest algorithm not used in DER encoding. */
    (void)type;

    /* Validate parameters. */
    if (key == NULL) {
        ret = 0;
    }

    if (ret == 1) {
        /* Make an RNG - create local or get global. */
        rng = wolfssl_make_rng(tmpRng, &initTmpRng);
        if (rng == NULL) {
            ret = 0;
        }
    }
    /* Sign the digest with the key using the RNG and put signature into buffer
     * update sigSz to be actual length.
     */
    if ((ret == 1) && (wc_ecc_sign_hash(digest, (word32)digestSz, sig, sigSz,
            rng, (ecc_key*)key->internal) != 0)) {
        ret = 0;
    }

    if (initTmpRng) {
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_RNG);
    }

    return ret;
}

/* Verify the signature with the digest and key.
 *
 * @param [in] type      Digest algorithm used to create digest. Unused.
 * @param [in] digest    Digest of the message to verify.
 * @param [in] digestSz  Size of the digest in bytes.
 * @param [in] sig       Buffer holding signature.
 * @param [in] sigSz     Size of signature data in bytes.
 * @param [in] key       EC key containing public key.
 * @return  1 when signature is valid.
 * @return  0 when signature is invalid or error.
 */
int wolfSSL_ECDSA_verify(int type, const unsigned char *digest, int digestSz,
    const unsigned char *sig, int sigSz, WOLFSSL_EC_KEY *key)
{
    int ret = 1;
    int verify = 0;

    WOLFSSL_ENTER("wolfSSL_ECDSA_verify");

    /* Digest algorithm not used in DER encoding. */
    (void)type;

    /* Validate parameters. */
    if (key == NULL) {
        ret = 0;
    }

    /* Verify signature using digest and key. */
    if ((ret == 1) && (wc_ecc_verify_hash(sig, (word32)sigSz, digest,
            (word32)digestSz, &verify, (ecc_key*)key->internal) != 0)) {
        ret = 0;
    }
    /* When no error, verification may still have failed - check now. */
    if ((ret == 1) && (verify != 1)) {
        WOLFSSL_MSG("wolfSSL_ECDSA_verify failed");
        ret = 0;
    }

    return ret;
}

/* End ECDSA */

/* Start ECDH */

#ifndef WOLF_CRYPTO_CB_ONLY_ECC
/* Compute the shared secret (key) using ECDH.
 *
 * KDF not supported.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [out] out      Buffer to hold key.
 * @param [in]  outLen   Length of buffer in bytes.
 * @param [in]  pubKey   Public key as an EC point.
 * @param [in]  privKey  EC key holding a private key.
 * @param [in]  kdf      Key derivation function to apply to secret.
 * @return  Length of computed key on success
 * @return  0 on error.
 */
int wolfSSL_ECDH_compute_key(void *out, size_t outLen,
    const WOLFSSL_EC_POINT *pubKey, WOLFSSL_EC_KEY *privKey,
    void *(*kdf) (const void *in, size_t inlen, void *out, size_t *outLen))
{
    int err = 0;
    word32 len = 0;
    ecc_key* key = NULL;
#if defined(ECC_TIMING_RESISTANT) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,0))
    int setGlobalRNG = 0;
#endif

    /* TODO: support using the KDF. */
    (void)kdf;

    WOLFSSL_ENTER("wolfSSL_ECDH_compute_key");

    /* Validate parameters. */
    if ((out == NULL) || (pubKey == NULL) || (pubKey->internal == NULL) ||
        (privKey == NULL) || (privKey->internal == NULL)) {
        WOLFSSL_MSG("Bad function arguments");
        err = 1;
    }

    /* Ensure internal EC key is set from external. */
    if ((!err) && (privKey->inSet == 0)) {
        WOLFSSL_MSG("No EC key internal set, do it");

        if (SetECKeyInternal(privKey) != 1) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            err = 1;
        }
    }

    if (!err) {
        int ret;

        /* Get the internal key. */
        key = (ecc_key*)privKey->internal;
        /* Set length into variable of type suitable for wolfSSL API. */
        len = (word32)outLen;

    #if defined(ECC_TIMING_RESISTANT) && !defined(HAVE_SELFTEST) && \
        (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,0))
        /* An RNG is needed. */
        if (key->rng == NULL) {
            key->rng = wolfssl_make_global_rng();
            /* RNG set and needs to be unset. */
            setGlobalRNG = 1;
        }
    #endif

        PRIVATE_KEY_UNLOCK();
        /* Create secret using wolfSSL. */
        ret = wc_ecc_shared_secret_ex(key, (ecc_point*)pubKey->internal,
            (byte *)out, &len);
        PRIVATE_KEY_LOCK();
        if (ret != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_shared_secret failed");
            err = 1;
        }
    }

#if defined(ECC_TIMING_RESISTANT) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,0))
    /* Remove global from key. */
    if (setGlobalRNG) {
        key->rng = NULL;
    }
#endif

    if (err) {
        /* Make returned value zero. */
        len = 0;
    }
    return (int)len;
}
#endif /* WOLF_CRYPTO_CB_ONLY_ECC */

/* End ECDH */

#ifndef NO_WOLFSSL_STUB
const WOLFSSL_EC_KEY_METHOD *wolfSSL_EC_KEY_OpenSSL(void)
{
    WOLFSSL_STUB("wolfSSL_EC_KEY_OpenSSL");

    return NULL;
}

WOLFSSL_EC_KEY_METHOD *wolfSSL_EC_KEY_METHOD_new(
        const WOLFSSL_EC_KEY_METHOD *meth)
{
    WOLFSSL_STUB("wolfSSL_EC_KEY_METHOD_new");

    (void)meth;

    return NULL;
}

void wolfSSL_EC_KEY_METHOD_free(WOLFSSL_EC_KEY_METHOD *meth)
{
    WOLFSSL_STUB("wolfSSL_EC_KEY_METHOD_free");

    (void)meth;
}

void wolfSSL_EC_KEY_METHOD_set_init(WOLFSSL_EC_KEY_METHOD *meth,
        void* a1, void* a2, void* a3, void* a4, void* a5, void* a6)
{
    WOLFSSL_STUB("wolfSSL_EC_KEY_METHOD_set_init");

    (void)meth;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    (void)a5;
    (void)a6;
}

void wolfSSL_EC_KEY_METHOD_set_sign(WOLFSSL_EC_KEY_METHOD *meth,
        void* a1, void* a2, void* a3)
{
    WOLFSSL_STUB("wolfSSL_EC_KEY_METHOD_set_sign");

    (void)meth;
    (void)a1;
    (void)a2;
    (void)a3;
}

const WOLFSSL_EC_KEY_METHOD *wolfSSL_EC_KEY_get_method(
        const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_STUB("wolfSSL_EC_KEY_get_method");

    (void)key;

    return NULL;
}

int wolfSSL_EC_KEY_set_method(WOLFSSL_EC_KEY *key,
        const WOLFSSL_EC_KEY_METHOD *meth)
{
    WOLFSSL_STUB("wolfSSL_EC_KEY_set_method");

    (void)key;
    (void)meth;

    return 0;
}

#endif /* !NO_WOLFSSL_STUB */

#endif /* OPENSSL_EXTRA */

#endif /* HAVE_ECC */

/*******************************************************************************
 * END OF EC API
 ******************************************************************************/

#endif /* !WOLFSSL_PK_EC_INCLUDED */

