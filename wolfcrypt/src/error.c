/* error.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of XSTRNCPY */
    #pragma warning(disable: 4996)
#endif

#ifndef NO_ERROR_STRINGS

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES_H
#include <wolfssl/debug-untrace-error-codes.h>
#endif

WOLFSSL_ABI
const char* wc_GetErrorString(int error)
{
    switch ((enum wolfCrypt_ErrorCodes)error) {

    case WC_SUCCESS:
        return "wolfCrypt generic success";

    case WC_FAILURE:
        return "wolfCrypt generic failure";

    case MP_MEM :
        return "MP integer dynamic memory allocation failed";

    case MP_VAL :
        return "MP integer invalid argument";

    case MP_WOULDBLOCK :
        return "MP integer non-blocking operation would block";

    case MP_NOT_INF:
        return "MP point not at infinity";

    case OPEN_RAN_E :
        return "opening random device error";

    case READ_RAN_E :
        return "reading random device error";

    case WINCRYPT_E :
        return "windows crypt init error";

    case CRYPTGEN_E :
        return "windows crypt generation error";

    case RAN_BLOCK_E :
        return "random device read would block error";

    case BAD_MUTEX_E :
        return "Bad mutex, operation failed";

    case WC_TIMEOUT_E:
        return "Timeout error";

    case WC_PENDING_E:
        return "wolfCrypt Operation Pending (would block / eagain) error";

    case WC_NO_PENDING_E:
        return "wolfCrypt operation not pending error";

    case MP_INIT_E :
        return "mp_init error state";

    case MP_READ_E :
        return "mp_read error state";

    case MP_EXPTMOD_E :
        return "mp_exptmod error state";

    case MP_TO_E :
        return "mp_to_xxx error state, can't convert";

    case MP_SUB_E :
        return "mp_sub error state, can't subtract";

    case MP_ADD_E :
        return "mp_add error state, can't add";

    case MP_MUL_E :
        return "mp_mul error state, can't multiply";

    case MP_MULMOD_E :
        return "mp_mulmod error state, can't multiply mod";

    case MP_MOD_E :
        return "mp_mod error state, can't mod";

    case MP_INVMOD_E :
        return "mp_invmod error state, can't inv mod";

    case MP_CMP_E :
        return "mp_cmp error state";

    case MP_ZERO_E :
        return "mp zero result, not expected";

    case MEMORY_E :
        return "out of memory error";

    case VAR_STATE_CHANGE_E :
        return "Variable state modified by different thread";

    case RSA_WRONG_TYPE_E :
        return "RSA wrong block type for RSA function";

    case RSA_BUFFER_E :
        return "RSA buffer error, output too small or input too big";

    case BUFFER_E :
        return "Buffer error, output too small or input too big";

    case ALGO_ID_E :
        return "Setting Cert AlgoID error";

    case PUBLIC_KEY_E :
        return "Setting Cert Public Key error";

    case DATE_E :
        return "Setting Cert Date validity error";

    case SUBJECT_E :
        return "Setting Cert Subject name error";

    case ISSUER_E :
        return "Setting Cert Issuer name error";

    case CA_TRUE_E :
        return "Setting basic constraint CA true error";

    case EXTENSIONS_E :
        return "Setting extensions error";

    case ASN_PARSE_E :
        return "ASN parsing error, invalid input";

    case ASN_VERSION_E :
        return "ASN version error, invalid number";

    case ASN_GETINT_E :
        return "ASN get big int error, invalid data";

    case ASN_RSA_KEY_E :
        return "ASN key init error, invalid input";

    case ASN_OBJECT_ID_E :
        return "ASN object id error, invalid id";

    case ASN_TAG_NULL_E :
        return "ASN tag error, not null";

    case ASN_EXPECT_0_E :
        return "ASN expect error, not zero";

    case ASN_BITSTR_E :
        return "ASN bit string error, wrong id";

    case ASN_UNKNOWN_OID_E :
        return "ASN oid error, unknown sum id";

    case ASN_DATE_SZ_E :
        return "ASN date error, bad size";

    case ASN_BEFORE_DATE_E :
        return "ASN date error, current date is before start of validity";

    case ASN_AFTER_DATE_E :
        return "ASN date error, current date is after expiration";

    case ASN_SIG_OID_E :
        return "ASN signature error, mismatched oid";

    case ASN_TIME_E :
        return "ASN time error, unknown time type";

    case ASN_INPUT_E :
        return "ASN input error, not enough data";

    case ASN_SIG_CONFIRM_E :
        return "ASN sig error, confirm failure";

    case ASN_SIG_HASH_E :
        return "ASN sig error, unsupported hash type";

    case ASN_SIG_KEY_E :
        return "ASN sig error, unsupported key type";

    case ASN_DH_KEY_E :
        return "ASN key init error, invalid input";

    case ASN_CRIT_EXT_E:
        return "X.509 Critical extension ignored or invalid";

    case ASN_ALT_NAME_E:
        return "ASN alternate name error";

    case ECC_BAD_ARG_E :
        return "ECC input argument wrong type, invalid input";

    case ASN_ECC_KEY_E :
        return "ECC ASN1 bad key data, invalid input";

    case ECC_CURVE_OID_E :
        return "ECC curve sum OID unsupported, invalid input";

    case BAD_FUNC_ARG :
        return "Bad function argument";

    case NOT_COMPILED_IN :
        return "Feature not compiled in";

    case UNICODE_SIZE_E :
        return "Unicode password too big";

    case NO_PASSWORD :
        return "No password provided by user";

    case ALT_NAME_E :
        return "Alt Name problem, too big";

    case AES_GCM_AUTH_E:
        return "AES-GCM Authentication check fail";

    case AES_CCM_AUTH_E:
        return "AES-CCM Authentication check fail";

    case AES_SIV_AUTH_E:
        return "AES-SIV authentication failure";

    case ASYNC_INIT_E:
        return "Async Init error";

    case COMPRESS_INIT_E:
        return "Compress Init error";

    case COMPRESS_E:
        return "Compress error";

    case DECOMPRESS_INIT_E:
        return "DeCompress Init error";

    case DECOMPRESS_E:
        return "DeCompress error";

    case BAD_ALIGN_E:
        return "Bad alignment error, no alloc help";

    case ASN_NO_SIGNER_E :
#ifndef OPENSSL_EXTRA
        return "ASN no signer error to confirm failure";
#else
        return "certificate verify failed";
#endif

    case ASN_CRL_CONFIRM_E :
        return "ASN CRL sig error, confirm failure";

    case ASN_CRL_NO_SIGNER_E :
        return "ASN CRL no signer error to confirm failure";

    case CRL_CERT_DATE_ERR:
        return "CRL date error";

    case ASN_OCSP_CONFIRM_E :
        return "ASN OCSP sig error, confirm failure";

    case ASN_NO_PEM_HEADER:
        return "ASN no PEM Header Error";

    case BAD_STATE_E:
        return "Bad state operation";

    case BAD_PADDING_E:
        return "Bad padding, message wrong length";

    case REQ_ATTRIBUTE_E:
        return "Setting cert request attributes error";

    case PKCS7_OID_E:
        return "PKCS#7 error: mismatched OID value";

    case PKCS7_RECIP_E:
        return "PKCS#7 error: no matching recipient found";

    case WC_PKCS7_WANT_READ_E:
        return "PKCS#7 operations wants more input, call again";

    case FIPS_NOT_ALLOWED_E:
        return "FIPS mode not allowed error";

    case ASN_NAME_INVALID_E:
        return "Name Constraint error";

    case RNG_FAILURE_E:
        return "Random Number Generator failed";

    case HMAC_MIN_KEYLEN_E:
        return "FIPS Mode HMAC Minimum Key or Salt Length error";

    case RSA_PAD_E:
        return "Rsa Padding error";

    case LENGTH_ONLY_E:
        return "Output length only set, not for other use error";

    case IN_CORE_FIPS_E:
        return "In Core Integrity check FIPS error";

    case AES_KAT_FIPS_E:
        return "AES Known Answer Test check FIPS error";

    case DES3_KAT_FIPS_E:
        return "DES3 Known Answer Test check FIPS error";

    case HMAC_KAT_FIPS_E:
        return "HMAC Known Answer Test check FIPS error";

    case RSA_KAT_FIPS_E:
        return "RSA Known Answer Test check FIPS error";

    case DRBG_KAT_FIPS_E:
        return "DRBG Known Answer Test check FIPS error";

    case DRBG_CONT_FIPS_E:
        return "DRBG Continuous Test FIPS error";

    case AESGCM_KAT_FIPS_E:
        return "AESGCM Known Answer Test check FIPS error";

    case THREAD_STORE_KEY_E:
        return "Thread Storage Key Create error";

    case THREAD_STORE_SET_E:
        return "Thread Storage Set error";

    case MAC_CMP_FAILED_E:
        return "MAC comparison failed";

    case IS_POINT_E:
        return "ECC is point on curve failed";

    case ECC_INF_E:
        return "ECC point at infinity error";

    case ECC_OUT_OF_RANGE_E:
        return "ECC Qx or Qy out of range error";

    case ECC_PRIV_KEY_E:
        return "ECC private key is not valid error";

    case SRP_CALL_ORDER_E:
        return "SRP function called in the wrong order error";

    case SRP_VERIFY_E:
        return "SRP proof verification error";

    case SRP_BAD_KEY_E:
        return "SRP bad key values error";

    case ASN_NO_SKID:
        return "ASN no Subject Key Identifier found error";

    case ASN_NO_AKID:
        return "ASN no Authority Key Identifier found error";

    case ASN_NO_KEYUSAGE:
        return "ASN no Key Usage found error";

    case SKID_E:
        return "Setting Subject Key Identifier error";

    case AKID_E:
        return "Setting Authority Key Identifier error";

    case KEYUSAGE_E:
        return "Key Usage value error";

    case EXTKEYUSAGE_E:
        return "Extended Key Usage value error";

    case CERTPOLICIES_E:
        return "Setting Certificate Policies error";

    case WC_INIT_E:
        return "wolfCrypt Initialize Failure error";

    case SIG_VERIFY_E:
        return "Signature verify error";

    case BAD_COND_E:
        return "Bad condition variable operation error";

    case SIG_TYPE_E:
        return "Signature type not enabled/available";

    case HASH_TYPE_E:
        return "Hash type not enabled/available";

    case WC_KEY_SIZE_E:
        return "Key size error, either too small or large";

    case ASN_COUNTRY_SIZE_E:
        return "Country code size error, either too small or large";

    case MISSING_RNG_E:
        return "RNG required but not provided";

    case ASN_PATHLEN_SIZE_E:
        return "ASN CA path length value too large error";

    case ASN_PATHLEN_INV_E:
        return "ASN CA path length larger than signer error";

    case BAD_KEYWRAP_ALG_E:
        return "Unsupported key wrap algorithm error";

    case BAD_KEYWRAP_IV_E:
        return "Decrypted AES key wrap IV does not match expected";

    case WC_CLEANUP_E:
        return "wolfcrypt cleanup failed";

    case ECC_CDH_KAT_FIPS_E:
        return "wolfcrypt FIPS ECC CDH Known Answer Test Failure";

    case DH_CHECK_PUB_E:
        return "DH Check Public Key failure";

    case BAD_PATH_ERROR:
        return "Bad path for opendir error";

    case ASYNC_OP_E:
        return "Async operation error";

    case BAD_OCSP_RESPONDER:
        return "Invalid OCSP Responder, missing specific key usage extensions";

    case ECC_PRIVATEONLY_E:
        return "Invalid use of private only ECC key";

    case WC_HW_E:
        return "Error with hardware crypto use";

    case WC_HW_WAIT_E:
        return "Hardware waiting on resource";

    case PSS_SALTLEN_E:
        return "PSS - Length of salt is too big for hash algorithm";

    case PRIME_GEN_E:
        return "Unable to find a prime for RSA key";

    case BER_INDEF_E:
        return "Unable to decode an indefinite length encoded message";

    case RSA_OUT_OF_RANGE_E:
        return "Ciphertext to decrypt is out of range";

    case RSAPSS_PAT_FIPS_E:
        return "wolfcrypt FIPS RSA-PSS Pairwise Agreement Test Failure";

    case ECDSA_PAT_FIPS_E:
        return "wolfcrypt FIPS ECDSA Pairwise Agreement Test Failure";

    case DH_KAT_FIPS_E:
        return "wolfcrypt FIPS DH Known Answer Test Failure";

    case AESCCM_KAT_FIPS_E:
        return "AESCCM Known Answer Test check FIPS error";

    case SHA3_KAT_FIPS_E:
        return "SHA-3 Known Answer Test check FIPS error";

    case ECDHE_KAT_FIPS_E:
        return "wolfcrypt FIPS ECDHE Known Answer Test Failure";

    case AES_GCM_OVERFLOW_E:
        return "AES-GCM invocation counter overflow";

    case AES_CCM_OVERFLOW_E:
        return "AES-CCM invocation counter overflow";

    case RSA_KEY_PAIR_E:
        return "RSA Key Pair-Wise Consistency check fail";

    case DH_CHECK_PRIV_E:
        return "DH Check Private Key failure";

    case WC_AFALG_SOCK_E:
        return "AF_ALG socket error";

    case WC_DEVCRYPTO_E:
        return "Error with /dev/crypto";

    case ZLIB_INIT_ERROR:
        return "zlib init error";

    case ZLIB_COMPRESS_ERROR:
        return "zlib compress error";

    case ZLIB_DECOMPRESS_ERROR:
        return "zlib decompress error";

    case PKCS7_NO_SIGNER_E:
        return "No signer in PKCS#7 signed data";

    case CRYPTOCB_UNAVAILABLE:
        return "Crypto callback unavailable";

    case PKCS7_SIGNEEDS_CHECK:
        return "Signature found but no certificate to verify";

    case PSS_SALTLEN_RECOVER_E:
        return "PSS - Salt length unable to be recovered";

    case CHACHA_POLY_OVERFLOW:
        return "wolfcrypt - ChaCha20_Poly1305 limit overflow 4GB";

    case ASN_SELF_SIGNED_E:
        return "ASN self-signed certificate error";

    case SAKKE_VERIFY_FAIL_E:
        return "SAKKE derivation verification error";

    case MISSING_IV:
        return "Required IV not set";

    case MISSING_KEY:
        return "Required key not set";

    case BAD_LENGTH_E:
        return "Value of length parameter is invalid.";

    case ECDSA_KAT_FIPS_E:
        return "wolfcrypt FIPS ECDSA Known Answer Test Failure";

    case RSA_PAT_FIPS_E:
        return "wolfcrypt FIPS RSA Pairwise Agreement Test Failure";

    case KDF_TLS12_KAT_FIPS_E:
        return "wolfcrypt FIPS TLSv1.2 KDF Known Answer Test Failure";

    case KDF_TLS13_KAT_FIPS_E:
        return "wolfcrypt FIPS TLSv1.3 KDF Known Answer Test Failure";

    case KDF_SSH_KAT_FIPS_E:
        return "wolfcrypt FIPS SSH KDF Known Answer Test Failure";

     case DHE_PCT_E:
        return "wolfcrypt DHE Pairwise Consistency Test Failure";

    case ECC_PCT_E:
        return "wolfcrypt ECDHE Pairwise Consistency Test Failure";

    case FIPS_PRIVATE_KEY_LOCKED_E:
        return "Cannot export private key, locked";

    case PROTOCOLCB_UNAVAILABLE:
        return "Protocol callback unavailable";

    case NO_VALID_DEVID:
        return "No valid device ID set";

    case IO_FAILED_E:
        return "Input/output failure";

    case SYSLIB_FAILED_E:
        return "System/library call failed";

    case USE_HW_PSK:
        return "Callback indicates that HW has PSK";

    case ENTROPY_RT_E:
        return "Entropy Repetition Test failed";

    case ENTROPY_APT_E:
        return "Entropy Adaptive Proportion Test failed";

    case ASN_DEPTH_E:
        return "Invalid ASN.1 - depth check";

    case ASN_LEN_E:
        return "ASN.1 length invalid";

    case SM4_GCM_AUTH_E:
        return "SM4-GCM Authentication check fail";

    case SM4_CCM_AUTH_E:
        return "SM4-CCM Authentication check fail";

    case FIPS_DEGRADED_E:
        return "FIPS module in DEGRADED mode";

    case AES_EAX_AUTH_E:
        return "AES-EAX Authentication check fail";

    case KEY_EXHAUSTED_E:
        return "Key no longer usable for operation";

    case FIPS_INVALID_VER_E:
        return "Invalid FIPS version defined, check length";

    case FIPS_DATA_SZ_E:
        return "FIPS Module Data too large adjust MAX_FIPS_DATA_SZ";

    case FIPS_CODE_SZ_E:
        return "FIPS Module Code too large adjust MAX_FIPS_CODE_SZ";

    case KDF_SRTP_KAT_FIPS_E:
        return "wolfCrypt FIPS SRTP-KDF Known Answer Test Failure";

    case ED25519_KAT_FIPS_E:
        return "wolfCrypt FIPS Ed25519 Known Answer Test Failure";

    case ED448_KAT_FIPS_E:
        return "wolfCrypt FIPS Ed448 Known Answer Test Failure";

    case PBKDF2_KAT_FIPS_E:
        return "wolfCrypt FIPS PBKDF2 Known Answer Test Failure";

    case WC_KEY_MISMATCH_E:
        return "key values mismatch";

    case DEADLOCK_AVERTED_E:
        return "Deadlock averted -- retry the call";

    case ASCON_AUTH_E:
        return "ASCON Authentication check fail";

    case WC_ACCEL_INHIBIT_E:
        return "Crypto acceleration is currently inhibited";

    case BAD_INDEX_E:
        return "Bad index";

    case INTERRUPTED_E:
        return "Process interrupted";

    case MLKEM_PUB_HASH_E:
        return "ML-KEM priv key's stored hash doesn't match encoded pub key";

    case BUSY_E:
        return "Object is busy";

    case ALREADY_E:
        return "Operation was redundant or preempted";

    case SEQ_OVERFLOW_E:
        return "Sequence counter would overflow";

    case MAX_CODE_E:
    case WC_SPAN1_MIN_CODE_E:
    case MIN_CODE_E:
    default:
        return "unknown error number";
    }
}

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES
#include <wolfssl/debug-trace-error-codes.h>
#endif


/* Error string functions for the SSL/TLS error code range.
 * These live here (not src/ssl.c) so they are available in WOLFCRYPT_ONLY
 * builds that define OPENSSL_EXTRA, avoiding a link-time dependency on
 * src/internal.c which is excluded from crypto-only builds. */
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES_H
#include <wolfssl/debug-untrace-error-codes.h>
#endif

#if !defined(NO_ERROR_STRINGS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED))
static const char* wolfSSL_ERR_reason_error_string_OpenSSL(unsigned long e)
{
    switch (e) {
    /* TODO: -WOLFSSL_X509_V_ERR_CERT_SIGNATURE_FAILURE. Conflicts with
     *       -WOLFSSL_ERROR_WANT_CONNECT.
     */
    case WOLFSSL_X509_V_ERR_CRL_HAS_EXPIRED:
        return "CRL has expired";

    case WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL:
        return "unable to get CRL";

    case WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID:
        return "certificate not yet valid";

    case WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED:
        return "certificate has expired";

    case WOLFSSL_X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        return "certificate signature failure";

    case WOLFSSL_X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        return "format error in certificate's notAfter field";

    case WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return "self-signed certificate in certificate chain";

    case WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return "unable to get local issuer certificate";

    case WOLFSSL_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        return "unable to verify the first certificate";

    case WOLFSSL_X509_V_ERR_CERT_CHAIN_TOO_LONG:
        return "certificate chain too long";

    case WOLFSSL_X509_V_ERR_CERT_REVOKED:
        return "certificate revoked";

    case WOLFSSL_X509_V_ERR_INVALID_CA:
        return "invalid CA certificate";

    case WOLFSSL_X509_V_ERR_PATH_LENGTH_EXCEEDED:
        return "path length constraint exceeded";

    case WOLFSSL_X509_V_ERR_CERT_REJECTED:
        return "certificate rejected";

    case WOLFSSL_X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
        return "subject issuer mismatch";

    case WOLFSSL_X509_V_ERR_HOSTNAME_MISMATCH:
        return "hostname mismatch";

    case WOLFSSL_X509_V_ERR_IP_ADDRESS_MISMATCH:
        return "IP address mismatch";

    default:
        return NULL;
    }
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL || HAVE_WEBSERVER || HAVE_MEMCACHED */

const char* wolfSSL_ERR_reason_error_string(unsigned long e)
{
#ifdef NO_ERROR_STRINGS

    (void)e;
    return "no support for error strings built in";

#else

    int error = (int)e;

    if (error > 0) {
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_WEBSERVER) || defined(HAVE_MEMCACHED)
    /* Check the OpenSSL error strings first. */
        const char* ossl_err = wolfSSL_ERR_reason_error_string_OpenSSL(e);
        if (ossl_err != NULL) {
            return ossl_err;
        }
    /* try to find error strings from wolfSSL */
#endif
        error = -error;
    }
    /* pass to wolfCrypt */
    if ((error <= WC_SPAN1_FIRST_E && error >= WC_SPAN1_MIN_CODE_E) ||
        (error <= WC_SPAN2_FIRST_E && error >= WC_SPAN2_MIN_CODE_E))
    {
        return wc_GetErrorString(error);
    }

    if (error == 0) {
#ifdef OPENSSL_EXTRA
        return "ok";
#else
        return "unknown error number";
#endif
    }

    switch ((enum wolfSSL_ErrorCodes)error) { /* // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange) */

    case UNSUPPORTED_SUITE :
        return "unsupported cipher suite";

    case INPUT_CASE_ERROR :
        return "input state error";

    case PREFIX_ERROR :
        return "bad index to key rounds";

    case MEMORY_ERROR :
        return "out of memory";

    case VERIFY_FINISHED_ERROR :
        return "verify problem on finished";

    case VERIFY_MAC_ERROR :
        return "verify mac problem";

    case PARSE_ERROR :
        return "parse error on header";

    case SIDE_ERROR :
        return "wrong client/server type";

    case NO_PEER_CERT : /* OpenSSL compatibility expects this exact text */
        return "peer did not return a certificate";

    case UNKNOWN_HANDSHAKE_TYPE :
        return "weird handshake type";

    case SOCKET_ERROR_E :
        return "error state on socket";

    case SOCKET_NODATA :
        return "expected data, not there";

    case INCOMPLETE_DATA :
        return "don't have enough data to complete task";

    case UNKNOWN_RECORD_TYPE :
        return "unknown type in record hdr";

    case DECRYPT_ERROR :
        return "error during decryption";

    case FATAL_ERROR :
        return "received alert fatal error";

    case ENCRYPT_ERROR :
        return "error during encryption";

    case FREAD_ERROR :
        return "fread problem";

    case NO_PEER_KEY :
        return "need peer's key";

    case NO_PRIVATE_KEY :
        return "need the private key";

    case NO_DH_PARAMS :
        return "server missing DH params";

    case RSA_PRIVATE_ERROR :
        return "error during rsa priv op";

    case MATCH_SUITE_ERROR :
        return "can't match cipher suite";

    case COMPRESSION_ERROR :
        return "compression mismatch error";

    case BUILD_MSG_ERROR :
        return "build message failure";

    case BAD_HELLO :
        return "client hello malformed";

    case DOMAIN_NAME_MISMATCH :
        return "peer subject name mismatch";

    case IPADDR_MISMATCH :
        return "peer ip address mismatch";

    case WANT_READ :
    case WOLFSSL_ERROR_WANT_READ_E :
        return "non-blocking socket wants data to be read";

    case NOT_READY_ERROR :
        return "handshake layer not ready yet, complete first";

    case VERSION_ERROR :
        return "record layer version error";

    case WANT_WRITE :
    case WOLFSSL_ERROR_WANT_WRITE_E :
        return "non-blocking socket write buffer full";

    case WOLFSSL_ERROR_WANT_CONNECT_E :
    case WOLFSSL_ERROR_WANT_ACCEPT_E :
        return "The underlying BIO was not yet connected";

    case WOLFSSL_ERROR_SYSCALL_E :
        return "fatal I/O error in TLS layer";

    case WOLFSSL_ERROR_WANT_X509_LOOKUP_E :
        return "application client cert callback asked to be called again";

    case BUFFER_ERROR :
        return "malformed buffer input error";

    case VERIFY_CERT_ERROR :
        return "verify problem on certificate";

    case VERIFY_SIGN_ERROR :
        return "verify problem based on signature";

    case CLIENT_ID_ERROR :
        return "psk client identity error";

    case SERVER_HINT_ERROR:
        return "psk server hint error";

    case PSK_KEY_ERROR:
        return "psk key callback error";

    case DUPE_ENTRY_E:
        return "duplicate entry error";

    case GETTIME_ERROR:
        return "gettimeofday() error";

    case GETITIMER_ERROR:
        return "getitimer() error";

    case SIGACT_ERROR:
        return "sigaction() error";

    case SETITIMER_ERROR:
        return "setitimer() error";

    case LENGTH_ERROR:
        return "record layer length error";

    case PEER_KEY_ERROR:
        return "can't decode peer key";

    case ZERO_RETURN:
    case WOLFSSL_ERROR_ZERO_RETURN_E :
        return "peer sent close notify alert";

    case ECC_CURVETYPE_ERROR:
        return "Bad ECC Curve Type or unsupported";

    case ECC_CURVE_ERROR:
        return "Bad ECC Curve or unsupported";

    case ECC_PEERKEY_ERROR:
        return "Bad ECC Peer Key";

    case ECC_MAKEKEY_ERROR:
        return "ECC Make Key failure";

    case ECC_EXPORT_ERROR:
        return "ECC Export Key failure";

    case ECC_SHARED_ERROR:
        return "ECC DHE shared failure";

    case NOT_CA_ERROR:
        return "Not a CA by basic constraint error";

    case BAD_CERT_MANAGER_ERROR:
        return "Bad Cert Manager error";

    case OCSP_CERT_REVOKED:
        return "OCSP Cert revoked";

    case CRL_CERT_REVOKED:
#ifdef OPENSSL_EXTRA
        return "certificate revoked";
#else
        return "CRL Cert revoked";
#endif

    case CRL_MISSING:
        return "CRL missing, not loaded";

    case CRYPTO_POLICY_FORBIDDEN:
        return "Operation forbidden by system crypto-policy";

    case MONITOR_SETUP_E:
        return "CRL monitor setup error";

    case THREAD_CREATE_E:
        return "Thread creation problem";

    case OCSP_NEED_URL:
        return "OCSP need URL";

    case OCSP_CERT_UNKNOWN:
        return "OCSP Cert unknown";

    case OCSP_LOOKUP_FAIL:
        return "OCSP Responder lookup fail";

    case MAX_CHAIN_ERROR:
        return "Maximum Chain Depth Exceeded";

    case MAX_CERT_EXTENSIONS_ERR:
        return "Maximum Cert Extension Exceeded";

    case COOKIE_ERROR:
        return "DTLS Cookie Error";

    case SEQUENCE_ERROR:
        return "DTLS Sequence Error";

    case SUITES_ERROR:
        return "Suites Pointer Error";

    case OUT_OF_ORDER_E:
        return "Out of order message, fatal";

    case BAD_KEA_TYPE_E:
        return "Bad KEA type found";

    case SANITY_CIPHER_E:
        return "Sanity check on ciphertext failed";

    case RECV_OVERFLOW_E:
        return "Receive callback returned more than requested";

    case GEN_COOKIE_E:
        return "Generate Cookie Error";

    case NO_PEER_VERIFY:
        return "Need peer certificate verify Error";

    case FWRITE_ERROR:
        return "fwrite Error";

    case CACHE_MATCH_ERROR:
        return "Cache restore header match Error";

    case UNKNOWN_SNI_HOST_NAME_E:
        return "Unrecognized host name Error";

    case UNKNOWN_MAX_FRAG_LEN_E:
        return "Unrecognized max frag len Error";

    case KEYUSE_SIGNATURE_E:
        return "Key Use digitalSignature not set Error";

    case KEYUSE_ENCIPHER_E:
        return "Key Use keyEncipherment not set Error";

    case EXTKEYUSE_AUTH_E:
        return "Ext Key Use server/client auth not set Error";

    case SEND_OOB_READ_E:
        return "Send Callback Out of Bounds Read Error";

    case SECURE_RENEGOTIATION_E:
        return "Invalid Renegotiation Error";

    case SESSION_TICKET_LEN_E:
        return "Session Ticket Too Long Error";

    case SESSION_TICKET_EXPECT_E:
        return "Session Ticket Error";

    case SCR_DIFFERENT_CERT_E:
        return "SCR Different cert error";

    case SESSION_SECRET_CB_E:
        return "Session Secret Callback Error";

    case NO_CHANGE_CIPHER_E:
        return "Finished received from peer before Change Cipher Error";

    case SANITY_MSG_E:
        return "Sanity Check on message order Error";

    case DUPLICATE_MSG_E:
        return "Duplicate HandShake message Error";

    case SNI_UNSUPPORTED:
        return "Protocol version does not support SNI Error";

    case SOCKET_PEER_CLOSED_E:
        return "Peer closed underlying transport Error";

    case BAD_TICKET_KEY_CB_SZ:
        return "Bad user session ticket key callback Size Error";

    case BAD_TICKET_MSG_SZ:
        return "Bad session ticket message Size Error";

    case BAD_TICKET_ENCRYPT:
        return "Bad user ticket callback encrypt Error";

    case DH_KEY_SIZE_E:
        return "DH key too small Error";

    case SNI_ABSENT_ERROR:
        return "No Server Name Indication extension Error";

    case RSA_SIGN_FAULT:
        return "RSA Signature Fault Error";

    case HANDSHAKE_SIZE_ERROR:
        return "Handshake message too large Error";

    case UNKNOWN_ALPN_PROTOCOL_NAME_E:
        return "Unrecognized protocol name Error";

    case BAD_CERTIFICATE_STATUS_ERROR:
        return "Bad Certificate Status Message Error";

    case OCSP_INVALID_STATUS:
        return "Invalid OCSP Status Error";

    case OCSP_WANT_READ:
        return "OCSP nonblock wants read";

    case RSA_KEY_SIZE_E:
        return "RSA key too small";

    case ECC_KEY_SIZE_E:
        return "ECC key too small";

    case DTLS_EXPORT_VER_E:
        return "Version needs updated after code change or version mismatch";

    case INPUT_SIZE_E:
        return "Input size too large Error";

    case CTX_INIT_MUTEX_E:
        return "Initialize ctx mutex error";

    case EXT_MASTER_SECRET_NEEDED_E:
        return "Extended Master Secret must be enabled to resume EMS session";

    case DTLS_POOL_SZ_E:
        return "Maximum DTLS pool size exceeded";

    case DECODE_E:
        return "Decode handshake message error";

    case WRITE_DUP_READ_E:
        return "Write dup write side can't read error";

    case WRITE_DUP_WRITE_E:
        return "Write dup read side can't write error";

    case INVALID_CERT_CTX_E:
        return "Certificate context does not match request or not empty";

    case BAD_KEY_SHARE_DATA:
        return "The Key Share data contains a group which is invalid";

    case MISSING_HANDSHAKE_DATA:
        return "The handshake message is missing required data";

    case BAD_BINDER: /* OpenSSL compatibility expects this exact text */
        return "binder does not verify";

    case EXT_NOT_ALLOWED:
        return "Extension type not allowed in handshake message type";

    case INVALID_PARAMETER:
        return "The security parameter is invalid";

    case UNSUPPORTED_EXTENSION:
        return "TLS Extension not requested by the client";

    case PRF_MISSING:
        return "Pseudo-random function is not enabled";

    case KEY_SHARE_ERROR:
        return "Key share extension did not contain a valid named group";

    case POST_HAND_AUTH_ERROR:
        return "Client will not do post handshake authentication";

    case HRR_COOKIE_ERROR:
        return "Cookie does not match one sent in HelloRetryRequest";

    case MCAST_HIGHWATER_CB_E:
        return "Multicast highwater callback returned error";

    case ALERT_COUNT_E:
        return "Alert Count exceeded error";

    case EXT_MISSING:
        return "Required TLS extension missing";

    case DTLS_RETX_OVER_TX:
        return "DTLS interrupting flight transmit with retransmit";

    case DH_PARAMS_NOT_FFDHE_E:
        return "Server DH parameters were not from the FFDHE set as required";

    case TCA_INVALID_ID_TYPE:
        return "TLS Extension Trusted CA ID type invalid";

    case TCA_ABSENT_ERROR:
        return "TLS Extension Trusted CA ID response absent";

    case TSIP_MAC_DIGSZ_E:
        return "TSIP MAC size invalid, must be sized for SHA-1 or SHA-256";

    case CLIENT_CERT_CB_ERROR:
        return "Error importing client cert or key from callback";

    case SSL_SHUTDOWN_ALREADY_DONE_E:
        return "Shutdown has already occurred";

    case TLS13_SECRET_CB_E:
        return "TLS1.3 Secret Callback Error";

    case DTLS_SIZE_ERROR:
        return "DTLS trying to send too much in single datagram error";

    case NO_CERT_ERROR:
        return "TLS1.3 No Certificate Set Error";

    case APP_DATA_READY:
        return "Application data is available for reading";

    case TOO_MUCH_EARLY_DATA:
        return "Too much early data";

    case SOCKET_FILTERED_E:
        return "Session stopped by network filter";

    case UNSUPPORTED_CERTIFICATE:
        return "Unsupported certificate type";

    case HTTP_TIMEOUT:
        return "HTTP timeout for OCSP or CRL req";

    case HTTP_RECV_ERR:
        return "HTTP Receive error";

    case HTTP_HEADER_ERR:
        return "HTTP Header error";

    case HTTP_PROTO_ERR:
        return "HTTP Protocol error";

    case HTTP_STATUS_ERR:
        return "HTTP Status error";

    case HTTP_VERSION_ERR:
        return "HTTP Version error";

    case HTTP_APPSTR_ERR:
        return "HTTP Application string error";

    case UNSUPPORTED_PROTO_VERSION:
        #ifdef OPENSSL_EXTRA
        return "WRONG_SSL_VERSION";
        #else
        return "bad/unsupported protocol version";
        #endif

    case FALCON_KEY_SIZE_E:
        return "Wrong key size for Falcon.";

    case DILITHIUM_KEY_SIZE_E:
        return "Wrong key size for Dilithium.";

    case QUIC_TP_MISSING_E:
        return "QUIC transport parameter not set";

    case QUIC_WRONG_ENC_LEVEL:
        return "QUIC data received at wrong encryption level";

    case DTLS_CID_ERROR:
        return "DTLS ConnectionID mismatch or missing";

    case DTLS_TOO_MANY_FRAGMENTS_E:
        return "Received too many fragmented messages from peer error";

    case DUPLICATE_TLS_EXT_E:
        return "Duplicate TLS extension in message.";

    case WOLFSSL_ALPN_NOT_FOUND:
        return "TLS extension not found";

    case WOLFSSL_BAD_CERTTYPE:
        return "Certificate type not supported";

    case WOLFSSL_BAD_STAT:
        return "bad status";

    case WOLFSSL_BAD_PATH:
        return "No certificates found at designated path";

    case WOLFSSL_BAD_FILETYPE:
        return "Data format not supported";

    case WOLFSSL_BAD_FILE:
        return "Input/output error on file";

    case WOLFSSL_NOT_IMPLEMENTED:
        return "Function not implemented";

    case WOLFSSL_UNKNOWN:
        return "Unknown algorithm (EVP)";

    case WOLFSSL_FATAL_ERROR:
        return "fatal error";

    case WOLFSSL_PEM_R_NO_START_LINE_E:
        return "No more matching objects found (PEM)";

    case WOLFSSL_PEM_R_PROBLEMS_GETTING_PASSWORD_E:
        return "Error getting password (PEM)";

    case WOLFSSL_PEM_R_BAD_PASSWORD_READ_E:
        return "Bad password (PEM)";

    case WOLFSSL_PEM_R_BAD_DECRYPT_E :
        return "Decryption failed (PEM)";

    case WOLFSSL_ASN1_R_HEADER_TOO_LONG_E:
        return "ASN header too long (compat)";

    case WOLFSSL_EVP_R_BAD_DECRYPT_E :
        return "Decryption failed (EVP)";

    case WOLFSSL_EVP_R_BN_DECODE_ERROR:
        return "Bignum decode error (EVP)";

    case WOLFSSL_EVP_R_DECODE_ERROR  :
        return "Decode error (EVP)";

    case WOLFSSL_EVP_R_PRIVATE_KEY_DECODE_ERROR:
        return "Private key decode error (EVP)";

    case SESSION_TICKET_NONCE_OVERFLOW:
        return "Session ticket nonce overflow";
    }

    return "unknown error number";

#endif /* NO_ERROR_STRINGS */
}

#ifdef WOLFSSL_DEBUG_TRACE_ERROR_CODES
#include <wolfssl/debug-trace-error-codes.h>
#endif

void SetErrorString(int error, char* str)
{
    XSTRNCPY(str, wolfSSL_ERR_reason_error_string((unsigned long)error), WOLFSSL_MAX_ERROR_SZ);
    str[WOLFSSL_MAX_ERROR_SZ-1] = 0;
}

char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data)
{
    WOLFSSL_ENTER("wolfSSL_ERR_error_string");
    if (data) {
        SetErrorString((int)errNumber, data);
        return data;
    }
    else {
        static char tmp[WOLFSSL_MAX_ERROR_SZ] = {0};
        SetErrorString((int)errNumber, tmp);
        return tmp;
    }
}


void wolfSSL_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
    WOLFSSL_ENTER("wolfSSL_ERR_error_string_n");
    if (len >= WOLFSSL_MAX_ERROR_SZ)
        wolfSSL_ERR_error_string(e, buf);
    else {
        WOLFSSL_MSG("Error buffer too short, truncating");
        if (len) {
            char tmp[WOLFSSL_MAX_ERROR_SZ];
            wolfSSL_ERR_error_string(e, tmp);
            XMEMCPY(buf, tmp, len-1);
            buf[len-1] = '\0';
        }
    }
}

void wc_ErrorString(int error, char* buffer)
{
    XSTRNCPY(buffer, wc_GetErrorString(error), WOLFSSL_MAX_ERROR_SZ);
    buffer[WOLFSSL_MAX_ERROR_SZ-1] = 0;
}
#endif /* !NO_ERROR_STRINGS */
