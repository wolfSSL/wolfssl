#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define HEAP_HINT NULL

static int devId = INVALID_DEVID;

#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

/* only for stack size check */
#ifdef HAVE_STACK_SIZE
    #include <wolfssl/ssl.h>
    #define err_sys err_sys_remap /* remap err_sys */
    #include <wolfssl/test.h>
    #undef err_sys
#endif

#ifdef HAVE_STACK_SIZE
static THREAD_RETURN err_sys(const char* msg, int es)
#else
static int err_sys(const char* msg, int es)
#endif
{
    printf("%s error = %d\n", msg, es);

    EXIT_TEST(-1);
}

#ifndef HAVE_STACK_SIZE
/* func_args from test.h, so don't have to pull in other stuff */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;
#endif /* !HAVE_STACK_SIZE */

int  sha256_test(void);

#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD wolfcrypt_test(void* args);
#else
int wolfcrypt_test(void* args);
#endif

typedef struct testVector {
    const char*  input;
    const char*  output;
    size_t inLen;
    size_t outLen;
} testVector;
#ifndef NO_SHA256
int sha256_test(void)
{
    wc_Sha256 sha;
    byte      hash[WC_SHA256_DIGEST_SIZE];
    byte      hashcopy[WC_SHA256_DIGEST_SIZE];
    int       ret = 0;

    testVector a, b, c;
    testVector test_sha[3];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "";
    a.output = "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9"
               "\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52"
               "\xb8\x55";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = WC_SHA256_DIGEST_SIZE;

    b.input  = "abc";
    b.output = "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
               "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
               "\x15\xAD";
    b.inLen  = XSTRLEN(b.input);
    b.outLen = WC_SHA256_DIGEST_SIZE;

    c.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    c.output = "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
               "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
               "\x06\xC1";
    c.inLen  = XSTRLEN(c.input);
    c.outLen = WC_SHA256_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;
    test_sha[2] = c;

    ret = wc_InitSha256_ex(&sha, HEAP_HINT, devId);
    if (ret != 0)
        return -2100;

    for (i = 0; i < times; ++i) {
        ret = wc_Sha256Update(&sha, (byte*)test_sha[i].input,
            (word32)test_sha[i].inLen);
        if (ret != 0)
            ERROR_OUT(-2110 - i, exit);
        ret = wc_Sha256GetHash(&sha, hashcopy);
        if (ret != 0)
            ERROR_OUT(-2120 - i, exit);
        ret = wc_Sha256Final(&sha, hash);
        if (ret != 0)
            ERROR_OUT(-2130 - i, exit);

        if (XMEMCMP(hash, test_sha[i].output, WC_SHA256_DIGEST_SIZE) != 0)
            ERROR_OUT(-2140 - i, exit);
        if (XMEMCMP(hash, hashcopy, WC_SHA256_DIGEST_SIZE) != 0)
            ERROR_OUT(-2150 - i, exit);
    }

    /* BEGIN LARGE HASH TEST */ {
    byte large_input[1024];
    const char* large_digest =
        "\x27\x78\x3e\x87\x96\x3a\x4e\xfb\x68\x29\xb5\x31\xc9\xba\x57\xb4"
        "\x4f\x45\x79\x7f\x67\x70\xbd\x63\x7f\xbf\x0d\x80\x7c\xbd\xba\xe0";

    for (i = 0; i < (int)sizeof(large_input); i++) {
        large_input[i] = (byte)(i & 0xFF);
    }
    times = 100;
#ifdef WOLFSSL_PIC32MZ_HASH
    wc_Sha256SizeSet(&sha, times * sizeof(large_input));
#endif
    for (i = 0; i < times; ++i) {
        ret = wc_Sha256Update(&sha, (byte*)large_input,
            (word32)sizeof(large_input));
        if (ret != 0)
            ERROR_OUT(-2160, exit);
    }
    ret = wc_Sha256Final(&sha, hash);
    if (ret != 0)
        ERROR_OUT(-2161, exit);
    if (XMEMCMP(hash, large_digest, WC_SHA256_DIGEST_SIZE) != 0)
        ERROR_OUT(-2162, exit);
    } /* END LARGE HASH TEST */

exit:

#ifdef NO_DO178
    wc_Sha256Free(&sha);
#endif
    return ret;
}
#endif

#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD wolfcrypt_test(void* args)
#else
int wolfcrypt_test(void* args)
#endif
{
    int ret;

    if (args)
        ((func_args*)args)->return_code = -1; /* error state */

#ifndef NO_SHA256
    if ( (ret = sha256_test()) != 0)
        return err_sys("SHA-256  test failed!\n", ret);
    else
        printf( "SHA-256  test passed!\n");
#endif

    EXIT_TEST(ret);
}

int main (void)
{
    func_args args;

    #ifdef HAVE_STACK_SIZE
        StackSizeCheck(&args, wolfcrypt_test);
    #else
        wolfcrypt_test(&args);
    #endif

    return 0;
}

