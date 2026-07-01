/* Bare-metal AArch64 firmware that runs a full native Falcon keygen -> sign ->
 * verify round-trip (levels 1 and 5) under qemu-system-aarch64 -machine virt,
 * exercising the NEON (float64x2_t + FMA) FFT on the signing/keygen path.
 * Result is reported over ARM semihosting: prints NEON_FFT_PASS / NEON_FFT_FAIL
 * and exits qemu.
 */
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ------------ ARM semihosting (SYS_WRITE0 = 0x04, SYS_EXIT = 0x18) --------- */
static long semihost(long op, void* arg)
{
    long ret;
    __asm__ volatile(
        "mov x0, %1\n\t"
        "mov x1, %2\n\t"
        "hlt #0xF000\n\t"
        "mov %0, x0\n\t"
        : "=r"(ret)
        : "r"(op), "r"(arg)
        : "x0", "x1", "memory");
    return ret;
}
static void sh_write0(const char* s) { (void)semihost(0x04, (void*)s); }
static void sh_exit(int code)
{
    /* ADP_Stopped_ApplicationExit = 0x20026 */
    long block[2];
    block[0] = 0x20026;
    block[1] = code;
    (void)semihost(0x18, block);
}

/* ------------------------- newlib heap (_sbrk) ---------------------------- */
extern char _heap_start;
extern char _heap_end;
static char* heap_ptr;
void* _sbrk(int incr);
void* _sbrk(int incr)
{
    char* prev;
    if (heap_ptr == 0) {
        heap_ptr = &_heap_start;
    }
    if (heap_ptr + incr > &_heap_end) {
        return (void*)-1;
    }
    prev = heap_ptr;
    heap_ptr += incr;
    return prev;
}

/* Deterministic test RNG (functional round-trip only; not for production). */
int custom_rand_generate_block(unsigned char* output, unsigned int sz)
{
    static uint32_t s = 0x12345678u;
    unsigned int i;
    for (i = 0; i < sz; ++i) {
        s = s * 1103515245u + 12345u;
        output[i] = (unsigned char)(s >> 24);
    }
    return 0;
}

static int falcon_roundtrip(byte level)
{
    falcon_key key;
    WC_RNG rng;
    byte sig[FALCON_MAX_SIG_SIZE];
    word32 sigLen = (word32)sizeof(sig);
    const char* msg = "wolfSSL NEON FFT Falcon self test";
    word32 msgLen = (word32)XSTRLEN(msg);
    int res = 0;
    int ret;

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return ret;
    }
    ret = wc_falcon_init(&key);
    if (ret == 0) {
        ret = wc_falcon_set_level(&key, level);
    }
    if (ret == 0) {
        ret = wc_falcon_make_key(&key, &rng);
    }
    if (ret == 0) {
        ret = wc_falcon_sign_msg((const byte*)msg, msgLen, sig, &sigLen, &key,
                &rng);
    }
    if (ret == 0) {
        ret = wc_falcon_verify_msg(sig, sigLen, (const byte*)msg, msgLen, &res,
                &key);
    }
    if (ret == 0 && res != 1) {
        ret = -1;
    }
    /* A tampered signature must be rejected. */
    if (ret == 0) {
        sig[sigLen - 1] ^= 0x01;
        res = 1;
        (void)wc_falcon_verify_msg(sig, sigLen, (const byte*)msg, msgLen, &res,
                &key);
        if (res == 1) {
            ret = -2;
        }
    }
    wc_falcon_free(&key);
    wc_FreeRng(&rng);
    return ret;
}

int main(void)
{
    int ret;

    if (wolfCrypt_Init() != 0) {
        sh_write0("NEON_FFT_FAIL: wolfCrypt_Init\n");
        sh_exit(1);
        return 1;
    }
    ret = falcon_roundtrip(1);
    if (ret == 0) {
        ret = falcon_roundtrip(5);
    }
    if (ret == 0) {
        sh_write0("NEON_FFT_PASS\n");
    }
    else {
        sh_write0("NEON_FFT_FAIL\n");
    }
    sh_exit(ret == 0 ? 0 : 1);
    return ret;
}
