/* clu_funcs.c
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

#include <wolfclu/wolfclu/clu_header_main.h>
#include <wolfclu/wolfclu/clu_log.h>
#include <wolfclu/wolfclu/clu_optargs.h>
#include <wolfclu/wolfclu/x509/clu_cert.h>        /* for PEM_FORM and DER_FORM */
#include <wolfclu/wolfclu/sign-verify/clu_sign.h> /* for RSA_SIG_VER, ECC_SIG_VER,
                                             ED25519_SIG_VER */
#include <wolfclu/wolfclu/x509/clu_parse.h>

#define SALT_SIZE       8
#define DES3_BLOCK_SIZE 24

#define MAX_ENTRY_NAME 64

static int loop = 0;

static const struct option crypt_algo_options[] = {
    /* AES */
    {"-aes-128-ctr", no_argument, 0, WOLFCLU_AES128CTR},
    {"-aes-192-ctr", no_argument, 0, WOLFCLU_AES192CTR},
    {"-aes-256-ctr", no_argument, 0, WOLFCLU_AES256CTR},
    {"-aes-128-cbc", no_argument, 0, WOLFCLU_AES128CBC},
    {"-aes-192-cbc", no_argument, 0, WOLFCLU_AES192CBC},
    {"-aes-256-cbc", no_argument, 0, WOLFCLU_AES256CBC},

    /* camellia */
    {"-camellia-128-cbc", no_argument, 0, WOLFCLU_CAMELLIA128CBC},
    {"-camellia-192-cbc", no_argument, 0, WOLFCLU_CAMELLIA192CBC},
    {"-camellia-256-cbc", no_argument, 0, WOLFCLU_CAMELLIA256CBC},

    /* 3des */
    {"-des-cbc", no_argument, 0, WOLFCLU_DESCBC},
    {"-d",       no_argument, 0, WOLFCLU_DECRYPT},

    {0, 0, 0, 0} /* terminal element */
};

/*
 * generic help function
 */
 void wolfCLU_help()
 {  WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "-help           Help, print out this help menu");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "Only set one of the following.\n");
    WOLFCLU_LOG(WOLFCLU_L0, "ca             Used for signing certificates");
    WOLFCLU_LOG(WOLFCLU_L0, "crl            Used for parsing CRL files");
    WOLFCLU_LOG(WOLFCLU_L0, "bench          Benchmark one of the algorithms");
    WOLFCLU_LOG(WOLFCLU_L0, "decrypt        Decrypt an encrypted file");
    WOLFCLU_LOG(WOLFCLU_L0, "dgst           Used for verifying a signature");
    WOLFCLU_LOG(WOLFCLU_L0, "dhparam        Used for creating dh params and keys");
    WOLFCLU_LOG(WOLFCLU_L0, "dsaparam       Used for creating dsa params and keys");
    WOLFCLU_LOG(WOLFCLU_L0, "ecc            Ecc signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "ecparam        Generate an ECC key and parameters");
    WOLFCLU_LOG(WOLFCLU_L0, "ed25519        Ed25519 signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "enc / encrypt  Encrypt a file or some user input");
    WOLFCLU_LOG(WOLFCLU_L0, "hash           Hash a file or input");
    WOLFCLU_LOG(WOLFCLU_L0, "md5            Creates an MD5 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "pkey           Used for key operations");
    WOLFCLU_LOG(WOLFCLU_L0, "req            Request for certificate generation");
    WOLFCLU_LOG(WOLFCLU_L0, "-rsa           Legacy RSA signing and signature verification");
    WOLFCLU_LOG(WOLFCLU_L0, "rsa            RSA key operations");
    WOLFCLU_LOG(WOLFCLU_L0, "x509           X509 certificate processing");
    WOLFCLU_LOG(WOLFCLU_L0, "verify         X509 certificate verify");
    WOLFCLU_LOG(WOLFCLU_L0, "pkcs12         Used for parsing PKCS12 files");
    WOLFCLU_LOG(WOLFCLU_L0, "s_client       Basic TLS client for testing"
                                           " connection");
    WOLFCLU_LOG(WOLFCLU_L0, "sha256         Creates a SHA256 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "sha384         Creates a SHA384 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "sha512         Creates a SHA512 hash");
    WOLFCLU_LOG(WOLFCLU_L0, "rand           Generates random data");
    WOLFCLU_LOG(WOLFCLU_L0, "version        Print wolfCLU/wolfSSL versions");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    /*optional flags*/
    WOLFCLU_LOG(WOLFCLU_L0, "Optional Flags.\n");
    WOLFCLU_LOG(WOLFCLU_L0, "-in             input file to manage");
    WOLFCLU_LOG(WOLFCLU_L0, "-out            file to output as a result of option");
    WOLFCLU_LOG(WOLFCLU_L0, "-pwd            user custom password");
    WOLFCLU_LOG(WOLFCLU_L0, "-iv             user custom IV (hex input only)");
    WOLFCLU_LOG(WOLFCLU_L0, "-key            user custom key(hex input only)");
    WOLFCLU_LOG(WOLFCLU_L0, "-verify         when using -iv and -key this will print result of"
           "                encryption for user verification."
           "                This flag takes no arguments.");
    WOLFCLU_LOG(WOLFCLU_L0, "-time           used by Benchmark, set time in seconds to run.");
    WOLFCLU_LOG(WOLFCLU_L0, "-verbose        display a more verbose help menu");
    WOLFCLU_LOG(WOLFCLU_L0, "-inform         input format of the certificate file [PEM/DER]");
    WOLFCLU_LOG(WOLFCLU_L0, "-outform        format to output [PEM/DER]");
    WOLFCLU_LOG(WOLFCLU_L0, "-output         used with -genkey option to specify which keys to"
           "                output [PUB/PRIV/KEYPAIR]");

    WOLFCLU_LOG(WOLFCLU_L0, "\nFor encryption: wolfssl -encrypt -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For decryption:   wolfssl -decrypt -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For hashing:      wolfssl -hash -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For benchmarking: wolfssl -bench -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For x509:         wolfssl -x509 -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For key creation: wolfssl -genkey -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For certificate creation: wolfssl -req -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For RSA sign/ver: wolfssl -rsa -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For ECC sign/ver: wolfssl -ecc -help");
    WOLFCLU_LOG(WOLFCLU_L0, "For ED25519 sign/ver: wolfssl -ed25519 -help");
 }

/*
 * verbose help function
 */
void wolfCLU_verboseHelp()
{
    int i;

    /* hash options */
    const char* algsenc[] = {        /* list of acceptable algorithms */
    "Algorithms:"
#ifndef NO_MD5
        ,"md5"
#endif
#ifndef NO_SHA
        ,"sha"
#endif
#ifndef NO_SHA256
        ,"sha256"
#endif
#ifdef WOLFSSL_SHA384
        ,"sha384"
#endif
#ifdef WOLFSSL_SHA512
        ,"sha512"
#endif
#ifdef HAVE_BLAKE2
        ,"blake2b"
#endif
#ifndef NO_CODING
    #ifdef WOLFSSL_BASE64_ENCODE
        ,"base64enc"
    #endif
        ,"base64dec"
#endif
    };

    /* benchmark options */
    const char* algsother[] = {      /* list of acceptable algorithms */
        "ALGS: "
#ifndef NO_AES
        , "aes-cbc"
#endif
#ifdef WOLFSSL_AES_COUNTER
        , "aes-ctr"
#endif
#ifndef NO_DES3
        , "3des"
#endif
#ifdef HAVE_CAMELLIA
        , "camellia"
#endif
#ifndef NO_MD5
        , "md5"
#endif
#ifndef NO_SHA
        , "sha"
#endif
#ifndef NO_SHA256
        , "sha256"
#endif
#ifdef WOLFSSL_SHA384
        , "sha384"
#endif
#ifdef WOLFSSL_SHA512
        , "sha512"
#endif
#ifdef HAVE_BLAKE2
        , "blake2b"
#endif
    };
    WOLFCLU_LOG(WOLFCLU_L0, "\nwolfssl Command Line Utility version %3.1f\n", VERSION);

    wolfCLU_help();

    WOLFCLU_LOG(WOLFCLU_L0, "Available En/De crypt Algorithms with current configure "
        "settings.\n");
#ifndef NO_AES
    WOLFCLU_LOG(WOLFCLU_L0, "aes-cbc-128\t\taes-cbc-192\t\taes-cbc-256");
#endif
#ifdef WOLFSSL_AES_COUNTER
    WOLFCLU_LOG(WOLFCLU_L0, "aes-ctr-128\t\taes-ctr-192\t\taes-ctr-256");
#endif
#ifndef NO_DES3
    WOLFCLU_LOG(WOLFCLU_L0, "3des-cbc-56\t\t3des-cbc-112\t\t3des-cbc-168");
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_LOG(WOLFCLU_L0, "camellia-cbc-128\tcamellia-cbc-192\t"
            "camellia-cbc-256");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "Available hashing algorithms with current configure settings:\n");

    for (i = 0; i < (int) sizeof(algsenc)/(int) sizeof(algsenc[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", algsenc[i]);
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Available benchmark tests with current configure settings:");
    WOLFCLU_LOG(WOLFCLU_L0, "(-a to test all)\n");

    for(i = 0; i < (int) sizeof(algsother)/(int) sizeof(algsother[0]); i++) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", algsother[i]);
    }
}

/*
 * Encrypt Usage
 */
void wolfCLU_encryptHelp()
{
    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable En/De crypt Algorithms with current configure "
            "settings.\n");
#ifndef NO_AES
    WOLFCLU_LOG(WOLFCLU_L0, "aes-cbc-128\t\taes-cbc-192\t\taes-cbc-256");
#endif
#ifdef WOLFSSL_AES_COUNTER
    WOLFCLU_LOG(WOLFCLU_L0, "aes-ctr-128\t\taes-ctr-192\t\taes-ctr-256");
#endif
#ifndef NO_DES3
    WOLFCLU_LOG(WOLFCLU_L0, "3des-cbc-56\t\t3des-cbc-112\t\t3des-cbc-168");
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_LOG(WOLFCLU_L0, "camellia-cbc-128\tcamellia-cbc-192\t"
            "camellia-cbc-256\n");
#endif

    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "Arguments:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in input file to read from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to write to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-pwd password input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-k another option for password input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-pass option for password source i.e pass:<password>");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-key hex key input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-iv  hex iv input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inkey input file for key");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-pbkdf2 use kdf version 2");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-md specify hash algo to use i.e md5, sha256");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-d decrypt the input file");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-p display debug information (key / iv ...)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-base64 handle decoding a base64 input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-nosalt do not use a salt input to kdf");
    WOLFCLU_LOG(WOLFCLU_L0, " ");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nENCRYPT USAGE: wolfssl -encrypt <-algorithm> -in <filename> "
           "-pwd <password> -out <output file name>\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -encrypt aes-cbc-128 -pwd Thi$i$myPa$$w0rd"
           " -in somefile.txt -out encryptedfile.txt\n");
}

/*
 * Decrypt Usage
 */
void wolfCLU_decryptHelp()
{
    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable En/De crypt Algorithms with current configure "
            "settings.\n");
#ifndef NO_AES
    WOLFCLU_LOG(WOLFCLU_L0, "aes-cbc-128\t\taes-cbc-192\t\taes-cbc-256");
#endif
#ifdef WOLFSSL_AES_COUNTER
    WOLFCLU_LOG(WOLFCLU_L0, "aes-ctr-128\t\taes-ctr-192\t\taes-ctr-256");
#endif
#ifndef NO_DES3
    WOLFCLU_LOG(WOLFCLU_L0, "3des-cbc-56\t\t3des-cbc-112\t\t3des-cbc-168");
#endif
#ifdef HAVE_CAMELLIA
    WOLFCLU_LOG(WOLFCLU_L0, "camellia-cbc-128\tcamellia-cbc-192\t"
            "camellia-cbc-256\n");
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nDECRYPT USAGE: wolfssl -decrypt <algorithm> -in <encrypted file> "
           "-pwd <password> -out <output file name>\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -decrypt aes-cbc-128 -pwd Thi$i$myPa$$w0rd"
           " -in encryptedfile.txt -out decryptedfile.txt\n");
}

/*
 * Hash Usage
 */
void wolfCLU_hashHelp()
{
    int i;

    /* hash options */
    const char* algsenc[] = {        /* list of acceptable algorithms */
    "Algorithms: "
#ifndef NO_MD5
        ,"md5"
#endif
#ifndef NO_SHA
        ,"sha"
#endif
#ifndef NO_SHA256
        ,"sha256"
#endif
#ifdef WOLFSSL_SHA384
        ,"sha384"
#endif
#ifdef WOLFSSL_SHA512
        ,"sha512"
#endif
#ifdef HAVE_BLAKE2
        ,"blake2b"
#endif
#ifndef NO_CODING
    #ifdef WOLFSSL_BASE64_ENCODE
        ,"base64enc"
    #endif
        ,"base64dec"
#endif
        };

    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable algorithms with current configure settings:");
    for (i = 0; i < (int) sizeof(algsenc)/(int) sizeof(algsenc[0]); i++) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", algsenc[i]);
    }
            /* encryption/decryption help lists options */
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nUSAGE: wolfssl -hash <-algorithm> -in <file to hash>");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -hash sha -in <some file>\n");
}

/*
 * Benchmark Usage
 */
void wolfCLU_benchHelp()
{
    int i;

    /* benchmark options */
    const char* algsother[] = {      /* list of acceptable algorithms */
        "ALGS: "
#ifndef NO_AES
        , "aes-cbc"
#endif
#ifdef WOLFSSL_AES_COUNTER
        , "aes-ctr"
#endif
#ifndef NO_DES3
        , "3des"
#endif
#ifdef HAVE_CAMELLIA
        , "camellia"
#endif
#ifndef NO_MD5
        , "md5"
#endif
#ifndef NO_SHA
        , "sha"
#endif
#ifndef NO_SHA256
        , "sha256"
#endif
#ifdef WOLFSSL_SHA384
        , "sha384"
#endif
#ifdef WOLFSSL_SHA512
        , "sha512"
#endif
#ifdef HAVE_BLAKE2
        , "blake2b"
#endif
    };

    WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable tests: (-a to test all)");
    WOLFCLU_LOG(WOLFCLU_L0, "Available tests with current configure settings:");
    for(i = 0; i < (int) sizeof(algsother)/(int) sizeof(algsother[0]); i++) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", algsother[i]);
    }
    WOLFCLU_LOG(WOLFCLU_L0, " ");
            /* encryption/decryption help lists options */
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "USAGE: wolfssl -bench [alg] -time [time in seconds [1-10]]"
           "       or\n       wolfssl -bench -time 10 -all (to test all)");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -bench aes-cbc -time 10"
           " -in encryptedfile.txt -out decryptedfile.txt\n");
}

void wolfCLU_certHelp()
{
    WOLFCLU_LOG(WOLFCLU_L0, "\n");
    WOLFCLU_LOG(WOLFCLU_L0, "-inform pem or der in format");
    WOLFCLU_LOG(WOLFCLU_L0, "-in the file to read from");
    WOLFCLU_LOG(WOLFCLU_L0, "-outform pem or der out format");
    WOLFCLU_LOG(WOLFCLU_L0, "-out output file to write to");
    WOLFCLU_LOG(WOLFCLU_L0, "-noout do not print output if set");
    WOLFCLU_LOG(WOLFCLU_L0, "-subject print out the subject name");
    WOLFCLU_LOG(WOLFCLU_L0, "-issuer  print out the issuer name");
    WOLFCLU_LOG(WOLFCLU_L0, "-serial  print out the serial number in hex");
    WOLFCLU_LOG(WOLFCLU_L0, "-dates   print out the valid dates of cert");
    WOLFCLU_LOG(WOLFCLU_L0, "-email   print out the subject names email address");
    WOLFCLU_LOG(WOLFCLU_L0, "-fingerprint print out the hash of the certificate in DER form");
    WOLFCLU_LOG(WOLFCLU_L0, "-purpose print out the certificates purpose");
    WOLFCLU_LOG(WOLFCLU_L0, "-hash print out the hash of the certificate subject name");
    WOLFCLU_LOG(WOLFCLU_L0, "-text print human readable text of X509");
    WOLFCLU_LOG(WOLFCLU_L0, "-modulus print out the RSA key modulus");
    WOLFCLU_LOG(WOLFCLU_L0, "-pubkey print out the Public Key");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nX509 USAGE: wolfssl -x509 -inform <PEM or DER> -in <filename> "
           "-outform <PEM or DER> -out <output file name> \n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -x509 -inform pem -in certs/"
           "ca-cert.pem -outform der -out certs/ca-cert-converted.der"
           "\n");
}

void wolfCLU_genKeyHelp()
{
    int i;

    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
    #ifndef NO_RSA
        ,"rsa"
    #endif
    #ifdef HAVE_ED25519
        ,"ed25519"
    #endif
    #ifdef HAVE_ECC
        ,"ecc"
    #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "Available keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }
    WOLFCLU_LOG(WOLFCLU_L0, "\n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\ngenkey USAGE:\nwolfssl -genkey <keytype> -size(optional) <bits> "
           "-out <filename> -outform <PEM or DER> -output <PUB/PRIV/KEYPAIR> \n");
    WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
    WOLFCLU_LOG(WOLFCLU_L0, "\nEXAMPLE: \n\nwolfssl -genkey rsa -size 2048 -out mykey -outform der "
           " -output KEYPAIR"
           "\n\nThe above command would output the files: mykey.priv "
           " and mykey.pub\nChanging the -output option to just PRIV would only"
           "\noutput the mykey.priv and using just PUB would only output"
           "\nmykey.pub\n");
}

void wolfCLU_signHelp(int keyType)
{
    int i;
    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
        #ifndef NO_RSA
        ,"rsa"
        #endif
        #ifdef HAVE_ED25519
        ,"ed25519"
        #endif
        #ifdef HAVE_ECC
        ,"ecc"
        #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }

        WOLFCLU_LOG(WOLFCLU_L0, "\n***************************************************************");
        switch(keyType) {
            #ifndef NO_RSA
            case RSA_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Sign Usage: \nwolfssl -rsa -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ED25519
            case ED25519_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Sign Usage: \nwolfssl -ed25519 -sign -inkey "
                       "<priv_key> -in <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ECC
            case ECC_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ECC Sign Usage: \nwolfssl -ecc -sign -inkey <priv_key>"
                       " -in <filename> -out <filename>\n");
                break;
            #endif
            default:
                WOLFCLU_LOG(WOLFCLU_L0, "No valid key type defined.\n");
        }
}

void wolfCLU_verifyHelp(int keyType) {
    int i;
    const char* keysother[] = { /* list of acceptable key types */
        "KEYS: "
        #ifndef NO_RSA
        ,"rsa"
        #endif
        #ifdef HAVE_ED25519
        ,"ed25519"
        #endif
        #ifdef HAVE_ECC
        ,"ecc"
        #endif
        };

        WOLFCLU_LOG(WOLFCLU_L0, "\nAvailable keys with current configure settings:");
        for(i = 0; i < (int) sizeof(keysother)/(int) sizeof(keysother[0]); i++) {
            WOLFCLU_LOG(WOLFCLU_L0, "%s", keysother[i]);
        }

        WOLFCLU_LOG(WOLFCLU_L0, "\n***************************************************************");
        switch(keyType) {
            #ifndef NO_RSA
            case RSA_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Verify with Private Key:"
                        "wolfssl -rsa -verify -inkey <priv_key>"
                        " -sigfile <filename> -out <filename>\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                WOLFCLU_LOG(WOLFCLU_L0, "RSA Verify with Public Key"
                       "wolfssl -rsa -verify -inkey <pub_key>"
                       " -sigfile <filename> -out <filename> -pubin\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ED25519
            case ED25519_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Verifiy with Private Key"
                       "wolfssl -ed25519 -verify -inkey "
                       "<priv_key> -sigfile <filename> -in <original>"
                       "\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                WOLFCLU_LOG(WOLFCLU_L0, "ED25519 Verifiy with Public Key"
                       "wolfssl -ed25519 -verify -inkey "
                       "<pub_key> -sigfile <filename> -in <original> -pubin"
                       "\n");
                WOLFCLU_LOG(WOLFCLU_L0, "***************************************************************");
                break;
            #endif
            #ifdef HAVE_ECC
            case ECC_SIG_VER:
                WOLFCLU_LOG(WOLFCLU_L0, "ECC Verify with Public Key"
                       "wolfssl -ecc -verify -inkey <pub_key>"
                       " -sigfile <signature> -in <original>\n");
                break;
            #endif
            default:
                WOLFCLU_LOG(WOLFCLU_L0, "No valid key type defined.\n");
        }
}

void wolfCLU_certgenHelp() {
    WOLFCLU_LOG(WOLFCLU_L0, "Arguments:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in input file to read from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to write to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-key public key to put into certificate request");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform der or pem format for '-in'");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-outform der or pem format for '-out'");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-config file to parse for certificate configuration");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-days number of days should be valid for");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-x509 generate self signed certificate");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-extensions overwrite the section to get extensions from");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-nodes no DES encryption on private key output");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-newkey generate the private key to use with req");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inkey private key to use with req");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-keyout file to output key to");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-subj use a specified subject name, ie O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-verify check the signature on the req");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-text output human readable text of req");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-noout do not print out the generated results");
}


/* return block size on success
 * alg and mode are null terminated strings that need free'd by the caller
 */
static int wolfCLU_parseAlgo(char* name, int* alg, char** mode, int* size)
{
    int     ret         = 0;        /* return variable */
    int     nameCheck   = 0;        /* check for acceptable name */
    int     modeCheck   = 0;        /* check for acceptable mode */
    int     i;
    char*   sz          = 0;        /* key size provided */
    char*   end         = 0;
    char*   tmpAlg      = NULL;
    char*   tmpMode     = NULL;

    const char* acceptAlgs[]  = {   /* list of acceptable algorithms */
        "Algorithms: "
#ifndef NO_AES
        , "aes"
#endif
#ifndef NO_DES3
        , "3des"
#endif
#ifdef HAVE_CAMELLIA
        , "camellia"
#endif
    };

    const char* acceptMode[] = {"cbc"
#ifdef WOLFSSL_AES_COUNTER
        , "ctr"
#endif
    };

    if (name == NULL || alg == NULL || mode == NULL || size == NULL) {
        wolfCLU_LogError("null input to get algo function");
        return WOLFCLU_FATAL_ERROR;
    }

    /* gets name after first '-' and before the second */
    tmpAlg = strtok_r(name, "-", &end);
    if (tmpAlg == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }


    for (i = 0; i < (int)(sizeof(acceptAlgs)/sizeof(acceptAlgs[0])); i++) {
        if (XSTRNCMP(tmpAlg, acceptAlgs[i], XSTRLEN(tmpAlg)) == 0 )
            nameCheck = 1;
    }

    /* gets mode after second "-" and before the third */
    if (nameCheck != 0) {
        /* gets size after third "-" */
        sz = strtok_r(NULL, "-", &end);
        if (sz == NULL) {
            return WOLFCLU_FATAL_ERROR;
        }
        *size = XATOI(sz);
    }

    tmpMode = strtok_r(NULL, "-", &end);
    if (tmpMode == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    for (i = 0; i < (int) (sizeof(acceptMode)/sizeof(acceptMode[0])); i++) {
        if (XSTRNCMP(tmpMode, acceptMode[i], XSTRLEN(tmpMode)) == 0)
            modeCheck = 1;
    }

    /* if name or mode doesn't match acceptable options */
    if (nameCheck == 0 || modeCheck == 0) {
        wolfCLU_LogError("Invalid entry, issue with algo name and mode");
        return WOLFCLU_FATAL_ERROR;
    }

    /* checks key sizes for acceptability */
    if (XSTRNCMP(tmpAlg, "aes", 3) == 0) {
    #ifdef NO_AES
        wolfCLU_LogError("AES not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = AES_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            wolfCLU_LogError("Invalid AES pwdKey size. Should be: %d", ret);
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (XSTRNCMP(tmpMode, "cbc", 3) == 0) {
            switch (*size) {
                case 128:
                    *alg = WOLFCLU_AES128CBC;
                    break;
                case 192:
                    *alg = WOLFCLU_AES192CBC;
                    break;
                case 256:
                    *alg = WOLFCLU_AES256CBC;
                    break;
            }
        }

        if (XSTRNCMP(tmpMode, "ctr", 3) == 0) {
            switch (*size) {
                case 128:
                    *alg = WOLFCLU_AES128CTR;
                    break;
                case 192:
                    *alg = WOLFCLU_AES192CTR;
                    break;
                case 256:
                    *alg = WOLFCLU_AES256CTR;
                    break;
            }
        }
    #endif
    }

    else if (XSTRNCMP(tmpAlg, "3des", 4) == 0) {
    #ifdef NO_DES3
        wolfCLU_LogError("3DES not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = DES3_BLOCK_SIZE;
        if (*size != 56 && *size != 112 && *size != 168) {
            wolfCLU_LogError("Invalid 3DES pwdKey size");
            ret = WOLFCLU_FATAL_ERROR;
        }
        *alg = WOLFCLU_DESCBC;
    #endif
    }

    else if (XSTRNCMP(tmpAlg, "camellia", 8) == 0) {
    #ifndef HAVE_CAMELLIA
        wolfCLU_LogError("CAMELIA not compiled in.");
        return NOT_COMPILED_IN;
    #else
        ret = CAMELLIA_BLOCK_SIZE;
        if (*size != 128 && *size != 192 && *size != 256) {
            wolfCLU_LogError("Invalid Camellia pwdKey size");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (XSTRNCMP(tmpMode, "cbc", 3) == 0) {
            switch (*size) {
                case 128:
                    *alg = WOLFCLU_CAMELLIA128CBC;
                    break;
                case 192:
                    *alg = WOLFCLU_CAMELLIA192CBC;
                    break;
                case 256:
                    *alg = WOLFCLU_CAMELLIA256CBC;
                    break;
            }
        }
    #endif
    }

    else {
        wolfCLU_LogError("Invalid algorithm: %s", tmpAlg);
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret >= 0) {
        int s;

        /* free any existing mode buffers */
        if (*mode != NULL)
            XFREE(*mode, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        if (ret >= 0) {
            s = (int)XSTRLEN(tmpMode) + 1;
            *mode = (char*)XMALLOC(s, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (*mode == NULL) {
                ret = MEMORY_E;
            }
        }

        if (ret >= 0) {
            XSTRNCPY(*mode, tmpMode, s);
        }
    }

    /* free up stuff in case of error */
    if (ret < 0) {
        if (*mode != NULL)
            XFREE(*mode, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *mode = NULL;
    }

    return ret;
}

static const char WOLFCLU_AES128CTR_NAME[] = "aes-128-ctr";
static const char WOLFCLU_AES192CTR_NAME[] = "aes-192-ctr";
static const char WOLFCLU_AES256CTR_NAME[] = "aes-256-ctr";
static const char WOLFCLU_AES128CBC_NAME[] = "aes-128-cbc";
static const char WOLFCLU_AES192CBC_NAME[] = "aes-192-cbc";
static const char WOLFCLU_AES256CBC_NAME[] = "aes-256-cbc";
static const char WOLFCLU_CAMELLIA128CBC_NAME[] = "camellia-128-cbc";
static const char WOLFCLU_CAMELLIA192CBC_NAME[] = "camellia-192-cbc";
static const char WOLFCLU_CAMELLIA256CBC_NAME[] = "camellia-256-cbc";
static const char WOLFCLU_DESCBC_NAME[] = "des-cbc";

static const char* algoName[] = {
    WOLFCLU_AES128CTR_NAME,
    WOLFCLU_AES192CTR_NAME,
    WOLFCLU_AES256CTR_NAME,
    WOLFCLU_AES128CBC_NAME,
    WOLFCLU_AES192CBC_NAME,
    WOLFCLU_AES256CBC_NAME,
    WOLFCLU_CAMELLIA128CBC_NAME,
    WOLFCLU_CAMELLIA192CBC_NAME,
    WOLFCLU_CAMELLIA256CBC_NAME,
    WOLFCLU_DESCBC_NAME,
};

/* support older name schemes MAX_AES_IDX is the maximum index for old AES algo
 * names */
#define MAX_AES_IDX 6
static const char* oldAlgoName[] = {
    "aes-ctr-128",
    "aes-ctr-192",
    "aes-ctr-256",
    "aes-cbc-128",
    "aes-cbc-192",
    "aes-cbc-256",
};


/* convert an old algo name into one optargs can handle */
static void wolfCLU_oldAlgo(int argc, char** argv, int maxIdx)
{
    int end;
    int i, j;

    end = (argc < maxIdx)? argc : maxIdx;
    for (i = 0; i < end; i++) {
        for (j = 0; j < MAX_AES_IDX; j++) {
            if (XSTRCMP(argv[i], oldAlgoName[j]) == 0) {
                argv[i] = (char*)algoName[j];
            }
        }
    }
}


/* get the WOLFSSL_EVP_CIPHER type from an algo enum value */
const WOLFSSL_EVP_CIPHER* wolfCLU_CipherTypeFromAlgo(int alg)
{
    switch (alg) {
        case WOLFCLU_AES128CTR:
            return wolfSSL_EVP_aes_128_ctr();
        case WOLFCLU_AES192CTR:
            return wolfSSL_EVP_aes_192_ctr();
        case WOLFCLU_AES256CTR:
            return wolfSSL_EVP_aes_256_ctr();
        case WOLFCLU_AES128CBC:
            return wolfSSL_EVP_aes_128_cbc();
        case WOLFCLU_AES192CBC:
            return wolfSSL_EVP_aes_192_cbc();
        case WOLFCLU_AES256CBC:
            return wolfSSL_EVP_aes_256_cbc();
#ifndef NO_DES3
        case WOLFCLU_DESCBC:
            return wolfSSL_EVP_des_cbc();
#endif
        default:
            return NULL;
    }
}


/*
 * finds algorithm for encryption/decryption
 * mode is a null terminated strings that need free'd by the caller
 */
int wolfCLU_getAlgo(int argc, char** argv, int* alg, char** mode, int* size)
{
    int ret = 0;
    int longIndex = 2;
    int option;
    char name[80];

    wolfCLU_oldAlgo(argc, argv, 3);
    XMEMSET(name, 0, sizeof(name));
    XSTRLCPY(name, argv[2], XSTRLEN(argv[2])+1);
    ret = wolfCLU_parseAlgo(name, alg, mode, size);

    /* next check for -cipher option passed through args */
    if (ret < 0) {
        optind = 0;
        opterr = 0; /* do not print out unknown options */
        while ((option = wolfCLU_GetOpt(argc, argv, "",
                       crypt_algo_options, &longIndex )) != -1) {
            switch (option) {
                /* AES */
                case WOLFCLU_AES128CTR:
                    XSTRNCPY(name, WOLFCLU_AES128CTR_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES192CTR:
                    XSTRNCPY(name, WOLFCLU_AES192CTR_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES256CTR:
                    XSTRNCPY(name, WOLFCLU_AES256CTR_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES128CBC:
                    XSTRNCPY(name, WOLFCLU_AES128CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES192CBC:
                    XSTRNCPY(name, WOLFCLU_AES192CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_AES256CBC:
                    XSTRNCPY(name, WOLFCLU_AES256CBC_NAME,
                            sizeof(name));
                    break;

                /* camellia */
                case WOLFCLU_CAMELLIA128CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA128CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_CAMELLIA192CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA192CBC_NAME,
                            sizeof(name));
                    break;

                case WOLFCLU_CAMELLIA256CBC:
                    XSTRNCPY(name, WOLFCLU_CAMELLIA256CBC_NAME,
                            sizeof(name));
                    break;

                /* 3des */
                case WOLFCLU_DESCBC:
                    XSTRNCPY(name, WOLFCLU_DESCBC_NAME,
                            sizeof(name));
                    break;

                case '?':
                case ':':
                    break;
                default:
                    /* do nothing. */
                    (void)ret;
            };

            if (XSTRLEN(name) > 0) {
                ret = wolfCLU_parseAlgo(name, alg, mode, size);
                XMEMSET(name, 0, sizeof(name));
            }
        }
    }

    return ret;
}


/*
 * adds character to end of string
 */
void wolfCLU_append(char* s, char c)
{
    int len = (int) XSTRLEN(s); /* length of string*/

    s[len] = c;
    s[len+1] = '\0';
}

/*
 * resets benchmarking loop
 */
void wolfCLU_stop(int signo)
{
    (void) signo; /* type cast to void for unused variable */
    loop = 0;
}

/*
 * gets current time durring program execution
 */
double wolfCLU_getTime(void)
{
#ifdef HAL_RTC_MODULE_ENABLED /* get time on HAL HW */
    extern RTC_HandleTypeDef hrtc;

    RTC_TimeTypeDef time;
    RTC_DateTypeDef date;
    uint32_t subsec = 0;

    /*get time and date here due to STM32 HW bug */
    HAL_RTC_GetTime(&hrtc, &time, FORMAT_BIN);
    HAL_RTC_GetDate(&hrtc, &date, FORMAT_BIN);
    (void) date;

    return ((double) time.Hours * 24) + ((double) time.Minutes * 60)
                    + (double) time.Seconds + ((double) subsec / 1000);

#elif !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) /* get time on WIN */
    struct timeval tv;

    gettimeofday(&tv, 0);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;

#else /* get time on unix */
    struct _timeb mytime1;

    _ftime64_s(&mytime1);
    return mytime1.time + mytime1.millitm / 1000;
#endif
}

/*
 * prints out stats for benchmarking
 */
void wolfCLU_stats(double start, int blockSize, int64_t blocks)
{
    double bytes;
    double time_total = wolfCLU_getTime() - start;

#if (BYTE_UNIT==KILOBYTE)
    char unit[]="KB";
#else
    char unit[]="MB";
#endif
    WOLFCLU_LOG(WOLFCLU_L0, "took %6.3f seconds, blocks = %llu", time_total,
            (unsigned long long)blocks);

    bytes = ((blocks * blockSize) / MEGABYTE) / time_total;
    WOLFCLU_LOG(WOLFCLU_L0, "Average %s/s = %8.1f", unit, bytes);
    if (blockSize != MEGABYTE) {
        WOLFCLU_LOG(WOLFCLU_L0, "Block size of this algorithm is: %d.\n", blockSize);
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Benchmarked using 1 %s at a time\n", unit);
    }
}


/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_version()
{
    WOLFCLU_LOG(WOLFCLU_L0, "You are using version %s of the wolfssl Command Line Utility."
        , LIBWOLFSSL_VERSION_STRING);
    return WOLFCLU_SUCCESS;
}

/* return 0 for not found and index found at otherwise */
int wolfCLU_checkForArg(const char* searchTerm, int length, int argc,
        char** argv)
{
    int i;
    int ret = 0;
    int argFound = 0;
    if (searchTerm == NULL) {
        return 0;
    }

    for (i = 0; i < argc; i++) {
        if (argv[i] == NULL) {
            break; /* stop checking if no more args*/
        }

        if (XSTRNCMP(searchTerm, "-help", length) == 0 &&
                   XSTRNCMP(argv[i], "-help", XSTRLEN(argv[i])) == 0 &&
                   (int)XSTRLEN(argv[i]) > 0) {
           return 1;

        }
        else if (XMEMCMP(argv[i], searchTerm, length) == 0 &&
                   (int)XSTRLEN(argv[i]) == length) {
            ret = i;
            if (argFound == 1) {
                wolfCLU_LogError("ERROR: argument found twice: \"%s\"", searchTerm);
                return USER_INPUT_ERROR;
            }
            argFound = 1;
        }
    }

    return ret;
}

int wolfCLU_checkOutform(char* outform)
{
    if (outform == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -outform [PEM/DER]");
        WOLFCLU_LOG(WOLFCLU_L0, "missing outform required argument");
        return USER_INPUT_ERROR;
    }

    wolfCLU_convertToLower(outform, (int)XSTRLEN(outform));
    if (XSTRNCMP(outform, "pem", 3) == 0) {
        return PEM_FORM;
    }
    else if (XSTRNCMP(outform, "der", 3) == 0) {
        return DER_FORM;
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -outform [PEM/DER]");
        WOLFCLU_LOG(WOLFCLU_L0, "\"%s\" is not a valid output format", outform);
    }
    return USER_INPUT_ERROR;
}

int wolfCLU_checkInform(char* inform)
{
    if (inform == NULL) {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -inform [PEM/DER]");
        WOLFCLU_LOG(WOLFCLU_L0, "missing inform required argument");
        return USER_INPUT_ERROR;
    }

    wolfCLU_convertToLower(inform, (int)XSTRLEN(inform));
    if (XSTRNCMP(inform, "pem", 3) == 0) {
        return PEM_FORM;
    }
    else if (XSTRNCMP(inform, "der", 3) == 0) {
        return DER_FORM;
    }
    else {
        WOLFCLU_LOG(WOLFCLU_L0, "Usage: -inform [PEM/DER]");
        WOLFCLU_LOG(WOLFCLU_L0, "\"%s\" is not a valid input format", inform);
    }
    return USER_INPUT_ERROR;
}


void wolfCLU_AddNameEntry(WOLFSSL_X509_NAME* name, int type, int nid, char* str)
{
    int i, sz;
    WOLFSSL_X509_NAME_ENTRY *entry;

    if (str != NULL) {
        /* strip off newline character if found at the end of str */
        i = (int)XSTRLEN((const char*)str);
        while (i >= 0) {
            if (str[i] == '\n') {
                str[i] = '\0';
                break;
            }
            i--;
        }

        /* treats a '.' string as 'do not add' */
        sz = (int)XSTRLEN((const char*)str);
        if (sz > 0 && XSTRCMP(str, ".") != 0) {
            entry = wolfSSL_X509_NAME_ENTRY_create_by_NID(NULL, nid,
                type, (const unsigned char*)str, sz);
            wolfSSL_X509_NAME_add_entry(name, entry, -1, 0);
            wolfSSL_X509_NAME_ENTRY_free(entry);
        }
    }
}


/* Input 'n' is a null-terminated string in the form of '/CN=name/C=company'
 * returns a newly created WOLFSSL_X509_NAME on success */
WOLFSSL_X509_NAME* wolfCLU_ParseX509NameString(const char* n, int nSz)
{
    int encoding = CTC_UTF8;
    int tagSz = 0;
    int nid;
    char* word, *end;
    char* deli = (char*)"/";
    char* entry = NULL;
    WOLFSSL_X509_NAME* ret = NULL;
    char  tag[5];

    if (n == NULL || nSz <= 0) {
        wolfCLU_LogError("unexpected null argument or size with parsing "
                "name");
        return NULL;
    }

    ret = wolfSSL_X509_NAME_new();
    if (ret == NULL) {
        wolfCLU_LogError("error allocating name structure");
        return NULL;
    }

    tag[0] = '/';
    for (word = strtok_r((char*)n, deli, &end); word != NULL;
            word = strtok_r(NULL, deli, &end)) {
        tagSz = (int)strcspn(word, "=");
        if (tagSz <= 0) {
            wolfCLU_LogError("error finding '=' char in name");
            wolfSSL_X509_NAME_free(ret);
            ret = NULL;
            break;
        }

        tagSz = tagSz + 1; /* include the '=' char */
        if (tagSz + 2 > (int)sizeof(tag)) { /* +2 for '/' and '\0' chars */
            wolfCLU_LogError("found a tag that was too large!");
            wolfSSL_X509_NAME_free(ret);
            ret = NULL;
            break;
        }
        else if (tagSz + 1 > nSz) {
            wolfCLU_LogError("error, entry would be past buffer end");
            wolfSSL_X509_NAME_free(ret);
            ret = NULL;
            break;
        }
        else {
            XMEMCPY(tag + 1, word, tagSz);
            tag[tagSz + 1] = '\0'; /* append terminating character */
        }

        if (ret != NULL) {
            entry = &word[tagSz];
            nid = wolfSSL_OBJ_sn2nid(tag);
            if (nid == NID_countryName) {
                encoding = CTC_PRINTABLE;
            }
            wolfCLU_AddNameEntry(ret, encoding, nid, entry);
        }
    }

    return ret;
}

size_t wolfCLU_getline(char **lineptr, size_t *len, FILE *fp)
{

    char line[MAX_ENTRY_NAME];

    *len = sizeof(line);

    *lineptr = NULL;
    if ((*lineptr = (char*)XMALLOC(*len, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER))
            == NULL) {
        XFREE(*lineptr, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return 0;
    }

    (*lineptr)[0] = '\0';

    while(fgets(line, sizeof(line), fp) != NULL) {
        size_t len_used = XSTRLEN(*lineptr);
        size_t line_used = XSTRLEN(line);

        if(*len - len_used < line_used) {
            *len *= 2;

            if((*lineptr = XREALLOC(*lineptr, *len, HEAP_HINT,
                            DYNAMIC_TYPE_TMP_BUFFER)) == NULL) {
                 return -1;
            }
        }

        XMEMCPY(*lineptr + len_used, line, line_used);
        len_used += line_used;
        (*lineptr)[len_used] = '\0';

        if((*lineptr)[len_used - 1] == '\n') {
            (*lineptr)[len_used - 1]='\0';
            return len_used;
        }
    }

    return -1;
}

/* returns WOLFCLU_SUCCESS on success */
int wolfCLU_CreateX509Name(WOLFSSL_X509_NAME* name)
{
    char   *in = NULL;
    size_t  inSz;
    size_t  ret;
    FILE *fout = stdout;
    FILE *fin = stdin; /* defaulting to stdin but using a fd variable to make it
                        * easy for expanding to other inputs */

    fprintf(fout, "Enter without data will result in the field being "
            "skipped.\nExamples of inputs are provided as [*]\n");
    fprintf(fout, "Country [US] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_PRINTABLE, NID_countryName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "State or Province [Montana] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_stateOrProvinceName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Locality [Bozeman] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_localityName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Organization Name [wolfSSL] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_organizationName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Organization Unit [engineering] : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_organizationalUnitName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Common Name : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_commonName, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    fprintf(fout, "Email Address : ");
    ret = wolfCLU_getline(&in, &inSz, fin);
    if (ret > 0) {
        wolfCLU_AddNameEntry(name, CTC_UTF8, NID_emailAddress, in);
    }
    XFREE(in, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return WOLFCLU_SUCCESS;
}


void wolfCLU_convertToLower(char* s, int sSz)
{
    int i;
    for (i = 0; i < sSz; i++) {
        s[i] = tolower(s[i]);
    }
}


void wolfCLU_ForceZero(void* mem, unsigned int len)
{
    volatile byte* z = (volatile byte*)mem;
    while (len--) *z++ = 0;
}

#ifndef WOLFCLU_NO_TERM_SUPPORT

int wolfCLU_GetPassword(char* password, int* passwordSz, char* arg)
{
    int ret = WOLFCLU_SUCCESS;

    if (password == NULL || passwordSz == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    XMEMSET(password, 0, *passwordSz);
    if (XSTRNCMP(arg, "stdin", 5) == 0) {
        if (XFGETS(password, MAX_PASSWORD_SIZE, stdin) == NULL) {
            wolfCLU_LogError("error getting password");
            ret = WOLFCLU_FATAL_ERROR;
        }
        if (ret == WOLFCLU_SUCCESS) {
            size_t idx = 0;
            *passwordSz = (int)XSTRLEN(password);

            /* span the string up to the first return line and chop
             * it off */
            if (XSTRSTR(password, "\r\n")) {
                idx = strcspn(password, "\r\n");
                if ((int)idx > *passwordSz) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    password[idx] = '\0';
                }
            }

            if (XSTRSTR(password, "\n")) {
                idx = strcspn(password, "\n");
                if ((int)idx > *passwordSz) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    password[idx] = '\0';
                }
            }

            *passwordSz = (int)XSTRLEN(password);
        }
    }
    else if (XSTRNCMP(arg, "pass:", 5) == 0) {
        XSTRNCPY(password, arg + 5, MAX_PASSWORD_SIZE);
        if (ret == WOLFCLU_SUCCESS) {
            *passwordSz = (int)XSTRLEN(password);
        }
    }
    else {
        wolfCLU_LogError("not supported password in type %s",
                arg);
        ret = WOLFCLU_FATAL_ERROR;
    }
    return ret;
}

#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
static int HideEcho(struct termios* originalTerm)
{
    struct termios newTerm;
    if (tcgetattr(STDIN_FILENO, originalTerm) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }

    XMEMCPY(&newTerm, originalTerm, sizeof(struct termios));
    newTerm.c_lflag &= ~ECHO;
    newTerm.c_lflag |= (ICANON | ECHONL);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}


static int ShowEcho(struct termios* originalTerm)
{
    if (tcsetattr(STDIN_FILENO, TCSANOW, originalTerm) != 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}

#else

static int HideEcho(DWORD* originalTerm)
{
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (GetConsoleMode(stdinHandle, originalTerm) == 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    DWORD newTerm = *originalTerm;
    newTerm &= ~ENABLE_ECHO_INPUT;
    if (SetConsoleMode(stdinHandle, newTerm) == 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}


static int ShowEcho(DWORD* originalTerm)
{
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (SetConsoleMode(stdinHandle, *originalTerm) == 0) {
        return WOLFCLU_FATAL_ERROR;
    }
    return WOLFCLU_SUCCESS;
}
#endif


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_GetStdinPassword(byte* password, word32* passwordSz)
{
    int ret;
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    struct termios originalTerm;
#else
    DWORD originalTerm;
#endif

    if (password == NULL || passwordSz == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    ret = HideEcho(&originalTerm);
    if (ret == WOLFCLU_SUCCESS) {
        printf("Input Password: ");
        if (fgets((char*)password, *passwordSz, stdin) == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            char* c = strpbrk((char*)password, "\r\n");
            if (c != NULL)
                *c = '\0';
        }
        *passwordSz = (word32)XSTRLEN((const char*)password);
        ShowEcho(&originalTerm);
    }
    return ret;
}
#endif

/* Not handling options char yet*/
int wolfCLU_GetOpt(int argc, char** argv, const char *options,
       const struct option *long_options, int *opt_index)
{
    int i     = optind; /* variable to keep track of starting option position */
    int index = 0;      /* index at which option was found */

    while (1) {

        /* set end to 1 if last option is reached */
        if (long_options[i].name == 0 ) {
            return WOLFCLU_FATAL_ERROR;
        }
        else {

            /* check if option is present in argv */
            index = wolfCLU_checkForArg(long_options[i].name, (int)XSTRLEN(long_options[i].name), argc, argv);
            optind++;

            /* if index matches *opt_index at first position or if index is found */
            if (index == *opt_index+1 || (*opt_index !=0 && index > 0)) {
                if (long_options[i].has_arg == 1) {
                    optarg=argv[index+1];
                }
                return long_options[i].val;
            }
        }

        i++;
    }

    (void) *options;

    return WOLFCLU_FATAL_ERROR;

}
