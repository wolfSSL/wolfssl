/* clu_optargs.h
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


#ifndef WOLFCLU_OPTARGS_H
#define WOLFCLU_OPTARGS_H

/* Enumerated types for long arguments */
enum {
    /* @temporary: implement modes as arguments */
    WOLFCLU_ENCRYPT = 1000,
    WOLFCLU_DECRYPT,
    WOLFCLU_CRYPT,
    WOLFCLU_BENCHMARK,
    WOLFCLU_HASH,
    WOLFCLU_MD,
    WOLFCLU_X509,
    WOLFCLU_REQUEST,
    WOLFCLU_GEN_KEY,
    WOLFCLU_ECPARAM,
    WOLFCLU_PKEY,
    WOLFCLU_PKCS12,
    WOLFCLU_CLIENT,
    WOLFCLU_CRL,
    WOLFCLU_RAND,
    WOLFCLU_RSALEGACY,
    WOLFCLU_CA,
    WOLFCLU_DSA,
    WOLFCLU_DH,

    WOLFCLU_CONNECT,
    WOLFCLU_STARTTLS,
    WOLFCLU_NODES,
    WOLFCLU_NOCERTS,
    WOLFCLU_NOKEYS,
    WOLFCLU_INFILE,
    WOLFCLU_CAFILE,
    WOLFCLU_OUTFILE,
    WOLFCLU_CHECK_CRL,
    WOLFCLU_PARTIAL_CHAIN,
    WOLFCLU_PASSWORD,
    WOLFCLU_PASSWORD_OUT,
    WOLFCLU_PASSWORD_SOURCE,
    WOLFCLU_RSAPUBIN,
    WOLFCLU_MODULUS,
    WOLFCLU_KEY,
    WOLFCLU_IV,
    WOLFCLU_NEW,
    WOLFCLU_NEWKEY,
    WOLFCLU_ALL,
    WOLFCLU_SIZE,
    WOLFCLU_EXPONENT,
    WOLFCLU_TIME,
    WOLFCLU_SIGN,
    WOLFCLU_SELFSIGN,
    WOLFCLU_VERIFY,
    WOLFCLU_DGST,
    WOLFCLU_VERBOSE,
    WOLFCLU_INKEY,
    WOLFCLU_OUTKEY,
    WOLFCLU_PUBIN,
    WOLFCLU_PUBOUT,
    WOLFCLU_PUBKEY,
    WOLFCLU_SIGFILE,
    WOLFCLU_CONFIG,
    WOLFCLU_EXTENSIONS,
    WOLFCLU_CURVE_NAME,
    WOLFCLU_DAYS,
    WOLFCLU_SUBJECT,
    WOLFCLU_INFORM,
    WOLFCLU_OUTFORM,
    WOLFCLU_NOOUT,
    WOLFCLU_TEXT_OUT,
    WOLFCLU_SILENT,
    WOLFCLU_OUTPUT,
    WOLFCLU_PBKDF2,
    WOLFCLU_BASE64,
    WOLFCLU_NOSALT,
    WOLFCLU_HELP,
    WOLFCLU_DEBUG,
    WOLFCLU_CHECK,
    WOLFCLU_VERIFY_RETURN_ERROR,
};

/* algos */
/* hashing */
#define WOLFCLU_CERT_SHA    2000
#define WOLFCLU_CERT_SHA224 2001
#define WOLFCLU_CERT_SHA256 2002
#define WOLFCLU_CERT_SHA384 2003
#define WOLFCLU_CERT_SHA512 2004
#define WOLFCLU_MD5         2005

/* public key */
#define WOLFCLU_RSA     2006
#define WOLFCLU_ECC     2007
#define WOLFCLU_ED25519 2008

/* AES */
#define WOLFCLU_AES128CTR 2009
#define WOLFCLU_AES192CTR 2010
#define WOLFCLU_AES256CTR 2011
#define WOLFCLU_AES128CBC 2012
#define WOLFCLU_AES192CBC 2013
#define WOLFCLU_AES256CBC 2014

/* camellia */
#define WOLFCLU_CAMELLIA128CBC 2015
#define WOLFCLU_CAMELLIA192CBC 2016
#define WOLFCLU_CAMELLIA256CBC 2017

/* 3des */
#define WOLFCLU_DESCBC 2018


#define WOLFCLU_PBKDF2 2
#define WOLFCLU_PBKDF1 1

#endif /* WOLFCLU_OPTARGS_H */

