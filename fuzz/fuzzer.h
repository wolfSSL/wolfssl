#ifndef fuzz_fuzzer_h
#define fuzz_fuzzer_h
#ifdef __cplusplus
    extern "C" {
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz);

#ifdef __cplusplus
    } /* extern "C" */
#endif
#endif
