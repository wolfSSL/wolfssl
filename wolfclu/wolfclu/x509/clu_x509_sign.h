/* clu_x509_sign.h
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


#ifndef WOLFCLU_X509_SIGN_H
#define WOLFCLU_X509_SIGN_H

typedef struct WOLFCLU_CERT_SIGN WOLFCLU_CERT_SIGN; 

WOLFCLU_CERT_SIGN* wolfCLU_CertSignNew(void);
int wolfCLU_CertSignFree(WOLFCLU_CERT_SIGN* csign);
void wolfCLU_CertSignSetSerial(WOLFCLU_CERT_SIGN* csign, WOLFSSL_BIO* s);
void wolfCLU_CertSignSetCA(WOLFCLU_CERT_SIGN* csign, WOLFSSL_X509* ca,
        void* key, int keyType);
void wolfCLU_CertSignSetHash(WOLFCLU_CERT_SIGN* csign,
        enum wc_HashType hashType);
void wolfCLU_CertSignSetDate(WOLFCLU_CERT_SIGN* csign, int d);
int wolfCLU_CertSign(WOLFCLU_CERT_SIGN* csign, WOLFSSL_X509* x509);
WOLFCLU_CERT_SIGN* wolfCLU_readSignConfig(char* config, char* sect);
int wolfCLU_CertSignAppendOut(WOLFCLU_CERT_SIGN* csign, char* out);
int wolfCLU_CertSignSetOut(WOLFCLU_CERT_SIGN* csign, char* out);
void wolfCLU_CertSignSetExt(WOLFCLU_CERT_SIGN* csign, char* ext);
#ifdef HAVE_CRL
void wolfCLU_CertSignSetCrl(WOLFCLU_CERT_SIGN* csign, char* crl, char* crlDir,
        int crlNumber);
#endif

#endif /* WOLFCLU_X509_SIGN_H */

