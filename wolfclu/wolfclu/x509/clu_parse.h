/* clu_parse.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#ifndef WOLFCLU_PARSE_H
#define WOLFCLU_PARSE_H

/**
 * @brief Function to print out DER public key
 *
 * @param bio the bio to print to
 * @param der der buffer to print out
 * @param derSz size of 'der' buffer
 *
 * @return returns WOLFCLU_SUCCESS on success
 */
int wolfCLU_printDerPubKey(WOLFSSL_BIO* bio, unsigned char* der, int derSz);

/**
 * @brief Function to print out DER private key
 *
 * @param bio the bio to print to
 * @param der der buffer to print out
 * @param derSz size of 'der' buffer
 * @param keyType is the type of PEM key to output, i.e RSA_TYPE, ECC_TYPE
 *
 * @return returns WOLFCLU_SUCCESS on success
 */
int wolfCLU_printDerPriKey(WOLFSSL_BIO* bio, unsigned char* der, int derSz,
        int keyType);


/**
 * @brief Generic function to print out DER from PEM
 *
 * @param bio the bio to print to
 * @param der der buffer to print out
 * @param derSz size of 'der' buffer
 * @param pemType is the type of PEM key to output, i.e RSA_TYPE, ECC_TYPE
 * @param heapType is the type of DYNAMIC heap to use
 *
 * @return returns WOLFCLU_SUCCESS on success
 */
int wolfCLU_printDer(WOLFSSL_BIO* bio, unsigned char* der, int derSz,
        int pemType, int heapType);

/**
 * @brief prints out the public key from a certificate
 *
 * @param x509 input to get public key from
 * @param out  PEM_FORM/DER_FORM of input
 *
 * @return returns WOLFCLU_SUCCESS on success
 */
int wolfCLU_printX509PubKey(WOLFSSL_X509* x509, WOLFSSL_BIO* out);

/**
 * @brief prints out extended key usage
 *
 * @param bio output bio
 * @param keyUsage bit map of key usage
 * @param indent number of leading spaces
 * @param flag if printing out NO for not supported items
 *
 * @return returns WOLFCLU_SUCCESS on success
 */
int wolfCLU_extKeyUsagePrint(WOLFSSL_BIO* bio, unsigned int keyUsage,
        int indent, int flag);

void wolfCLU_AddNameEntry(WOLFSSL_X509_NAME* name, int type, int nid, char* str);
#endif /* WOLFCLU_PARSE_H */
