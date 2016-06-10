/* ksdk_port.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc. All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */

#ifndef _KSDK_PORT_H_
#define _KSDK_PORT_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/tfm.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>

/* software algorithm, by wolfcrypt */
#if defined(FREESCALE_LTC_TFM)
	void wolfcrypt_fp_mul(fp_int *A, fp_int *B, fp_int *C);
	int wolfcrypt_fp_mod(fp_int *a, fp_int *b, fp_int *c);
	int wolfcrypt_fp_mulmod(fp_int *a, fp_int *b, fp_int *c, fp_int *d);
	int wolfcrypt_fp_mod(fp_int *a, fp_int *b, fp_int *c);
	int wolfcrypt_fp_invmod(fp_int *a, fp_int *b, fp_int *c);
	int _wolfcrypt_fp_exptmod(fp_int *G, fp_int *X, fp_int *P, fp_int *Y);
	int _fp_exptmod(fp_int *G, fp_int *X, fp_int *P, fp_int *Y);
	#ifndef NO_RSA
		#include <wolfssl/wolfcrypt/rsa.h>
		int wc_RsaFunction(const byte *in, word32 inLen, byte *out, word32 *outLen, int type, RsaKey *key);
	#endif
#endif /* FREESCALE_LTC_TFM */

#if defined(FREESCALE_LTC_ECC)

	#include "fsl_ltc.h"

	typedef enum _fsl_ltc_ecc_coordinate_system
	{
	    kLTC_Weierstrass = 0U, /*!< Point coordinates on an elliptic curve in Weierstrass form */
	    kLTC_Curve25519 = 1U,  /*!< Point coordinates on an Curve25519 elliptic curve in Montgomery form */
	    kLTC_Ed25519 = 2U,     /*!< Point coordinates on an Ed25519 elliptic curve in twisted Edwards form */
	} fsl_ltc_ecc_coordinate_system_t;

	int wc_ecc_point_add(ecc_point *mG, ecc_point *mQ, ecc_point *mR, mp_int *m);

	#ifdef HAVE_CURVE25519
		int wc_curve25519(ECPoint *q, byte *n, ECPoint *p, fsl_ltc_ecc_coordinate_system_t type);
		ECPoint *wc_curve25519_GetBasePoint(void);
		status_t LTC_PKHA_Curve25519ToWeierstrass(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut);
		status_t LTC_PKHA_WeierstrassToCurve25519(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut);
		status_t LTC_PKHA_Curve25519ComputeY(ltc_pkha_ecc_point_t *ltcPoint);
	#endif

	#ifdef HAVE_ED25519
		status_t LTC_PKHA_Ed25519ToWeierstrass(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut);
		status_t LTC_PKHA_WeierstrassToEd25519(const ltc_pkha_ecc_point_t *ltcPointIn, ltc_pkha_ecc_point_t *ltcPointOut);
		status_t LTC_PKHA_Ed25519_PointMul(const ltc_pkha_ecc_point_t *ltcPointIn,
		                                   const uint8_t *N,
		                                   size_t sizeN,
		                                   ltc_pkha_ecc_point_t *ltcPointOut,
		                                   fsl_ltc_ecc_coordinate_system_t typeOut);
		const ltc_pkha_ecc_point_t *LTC_PKHA_Ed25519_BasePoint(void);
		status_t LTC_PKHA_Ed25519_PointDecompress(const uint8_t *pubkey, size_t pubKeySize, ltc_pkha_ecc_point_t *ltcPointOut);
		status_t LTC_PKHA_sc_reduce(uint8_t *a);
		status_t LTC_PKHA_sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c);
		status_t LTC_PKHA_SignatureForVerify(uint8_t *rcheck, const unsigned char *a, const unsigned char *b, ed25519_key *key);
		status_t LTC_PKHA_Ed25519_Compress(const ltc_pkha_ecc_point_t *ltcPointIn, uint8_t *p);
	#endif

#endif /* FREESCALE_LTC_ECC */

#endif /* _KSDK_PORT_H_ */
