/* Bare-metal STM32H563 (Cortex-M33) firmware that drives wolfCrypt's native
 * Falcon-512 verify path under m33mu, exercising the DSP (SMLAxx / SMUAD +
 * packed halfword) NTT/pointwise/norm that auto-enables on __ARM_FEATURE_DSP.
 *
 * BKPT markers:
 *   0x7f: valid signature accepted AND tampered signature rejected (success)
 *   0x7c: valid signature was rejected
 *   0x7d: tampered signature was accepted
 *   0x71: verify returned an operational error
 *   0x70: setup/init failure
 */
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "kat.h"

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern void __libc_init_array(void);

#define HEAP_PAINT_WORD   0x48454150u
#define STACK_PAINT_WORD  0x5354414bu
#define STACK_PAINT_BYTES (64u * 1024u)
#define STACK_GUARD_BYTES 512u

static __attribute__((noinline)) void bkpt_success(void)
    { __asm volatile("bkpt #0x7f"); }
static __attribute__((noinline)) void bkpt_valid_rejected(void)
    { __asm volatile("bkpt #0x7c"); }
static __attribute__((noinline)) void bkpt_tamper_accepted(void)
    { __asm volatile("bkpt #0x7d"); }
static __attribute__((noinline)) void bkpt_verify_error(void)
    { __asm volatile("bkpt #0x71"); }
static __attribute__((noinline)) void bkpt_setup_fail(void)
    { __asm volatile("bkpt #0x70"); }

static void spin_forever(void)
{
    while (1) {
        __asm volatile("wfi");
    }
}

static void paint_words(uint32_t* start, uint32_t* end, uint32_t word)
{
    while (start < end) {
        *start++ = word;
    }
}

static void paint_runtime_ram(void)
{
    uintptr_t sp_now;
    uintptr_t heap_start;
    uintptr_t paint_limit;
    uintptr_t stack_start;

    __asm volatile("mov %0, sp" : "=r"(sp_now));
    heap_start = (uintptr_t)&_ebss;
    if (sp_now <= (heap_start + STACK_GUARD_BYTES)) {
        return;
    }
    paint_limit = sp_now - STACK_GUARD_BYTES;
    paint_words((uint32_t*)heap_start, (uint32_t*)paint_limit, HEAP_PAINT_WORD);
    stack_start = paint_limit;
    if (stack_start > (heap_start + STACK_PAINT_BYTES)) {
        stack_start -= STACK_PAINT_BYTES;
    }
    else {
        stack_start = heap_start;
    }
    paint_words((uint32_t*)stack_start, (uint32_t*)paint_limit, STACK_PAINT_WORD);
}

/* Some wolfCrypt units reference this even under WC_NO_RNG builds. */
int custom_rand_generate_block(unsigned char* output, unsigned int sz);
int custom_rand_generate_block(unsigned char* output, unsigned int sz)
{
    unsigned int i;
    for (i = 0; i < sz; ++i) {
        output[i] = (unsigned char)(0xa5u ^ (unsigned char)i);
    }
    return 0;
}

/* Observable state for fault analysis / m33mu symbol dumps. */
volatile int    g_init_ret;
volatile int    g_import_ret;
volatile int    g_verify_ret;
volatile int    g_valid_res;
volatile int    g_tamper_res;

/* Returns 0 on full success, or a negative marker for the failure kind. */
static int run_falcon_verify(void)
{
    falcon_key key;
    int res = 0;
    int ret;
    word32 msgLen = (word32)XSTRLEN(FALCON_KAT_MSG);
    static byte sigbuf[FALCON512_SIGLEN];

    ret = wc_falcon_init(&key);
    if (ret != 0) return -700;
    ret = wc_falcon_set_level(&key, 1);
    if (ret != 0) { wc_falcon_free(&key); return -700; }
    ret = wc_falcon_import_public(FALCON512_pk, (word32)sizeof(FALCON512_pk),
            &key);
    g_import_ret = ret;
    if (ret != 0) { wc_falcon_free(&key); return -700; }

    /* 1) A genuine signature must verify (res == 1). */
    XMEMCPY(sigbuf, FALCON512_sig, FALCON512_SIGLEN);
    res = 0;
    ret = wc_falcon_verify_msg(sigbuf, FALCON512_SIGLEN,
            (const byte*)FALCON_KAT_MSG, msgLen, &res, &key);
    g_verify_ret = ret;
    g_valid_res  = res;
    if (ret != 0) { wc_falcon_free(&key); return -710; }
    if (res != 1) { wc_falcon_free(&key); return -720; }

    /* 2) Flip a byte in the compressed body; it must NOT verify. */
    sigbuf[FALCON512_SIGLEN - 1] ^= 0x01;
    res = 1;
    (void)wc_falcon_verify_msg(sigbuf, FALCON512_SIGLEN,
            (const byte*)FALCON_KAT_MSG, msgLen, &res, &key);
    g_tamper_res = res;
    wc_falcon_free(&key);
    if (res == 1) return -730;

    return 0;
}

int main(void)
{
    int ret;

    paint_runtime_ram();

    g_init_ret = wolfCrypt_Init();
    if (g_init_ret != 0) {
        bkpt_setup_fail();
        spin_forever();
    }

    ret = run_falcon_verify();
    if (ret == 0) {
        bkpt_success();          /* 0x7f */
    }
    else if (ret == -720) {
        bkpt_valid_rejected();   /* 0x7c */
    }
    else if (ret == -730) {
        bkpt_tamper_accepted();  /* 0x7d */
    }
    else if (ret == -710) {
        bkpt_verify_error();     /* 0x71 */
    }
    else {
        bkpt_setup_fail();       /* 0x70 */
    }
    spin_forever();
    return 0;
}

void Reset_Handler(void);
void Reset_Handler(void)
{
    uint32_t* src;
    uint32_t* dst;

    src = &_sidata;
    for (dst = &_sdata; dst < &_edata; ++dst) {
        *dst = *src++;
    }
    for (dst = &_sbss; dst < &_ebss; ++dst) {
        *dst = 0;
    }
    __libc_init_array();
    (void)main();
    bkpt_setup_fail();
    spin_forever();
}
