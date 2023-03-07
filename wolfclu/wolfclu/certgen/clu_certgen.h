#include <stdio.h>
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

#define HEAP_HINT NULL
#define FOURK_SZ 4096

enum {
    SHA_HASH,
    SHA_HASH224,
    SHA_HASH256,
    SHA_HASH384,
    SHA_HASH512
};

int make_self_signed_rsa_certificate(char*, char*, int);

int make_self_signed_ed25519_certificate(char*, char*);
