/* test_digest.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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


#define DIGEST_INIT_TEST(type, name)                                           \
do {                                                                           \
    type dgst;                                                                 \
                                                                               \
    /* Test bad arg. */                                                        \
    ExpectIntEQ(wc_Init##name(NULL, HEAP_HINT, INVALID_DEVID),                 \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    /* Test good arg. */                                                       \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
    wc_##name##_Free(&dgst);                                                   \
                                                                               \
    wc_##name##_Free(NULL);                                                    \
} while (0)

#define DIGEST_INIT_AND_INIT_EX_TEST(type, name)                               \
    type dgst;                                                                 \
                                                                               \
    /* Test bad arg. */                                                        \
    ExpectIntEQ(wc_Init##name(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));           \
    ExpectIntEQ(wc_Init##name##_ex(NULL, HEAP_HINT, INVALID_DEVID),            \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    /* Test good arg. */                                                       \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
    wc_##name##Free(&dgst);                                                    \
                                                                               \
    ExpectIntEQ(wc_Init##name##_ex(&dgst, HEAP_HINT, INVALID_DEVID), 0);       \
    wc_##name##Free(&dgst);                                                    \
                                                                               \
    wc_##name##Free(NULL)

#define DIGEST_INIT_ONLY_TEST(type, name)                                      \
do {                                                                           \
    type dgst;                                                                 \
                                                                               \
    /* Test bad arg. */                                                        \
    wc_Init##name(NULL);                                                       \
                                                                               \
    /* Test good arg. */                                                       \
    wc_Init##name(&dgst);                                                      \
} while (0)

#define DIGEST_UPDATE_TEST(type, name)                                         \
    type dgst;                                                                 \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Pass in bad values. */                                                  \
    ExpectIntEQ(wc_##name##Update(NULL, NULL, 1),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Update(&dgst, NULL, 1),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Update(NULL, NULL, 0),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Update(NULL, (byte*)"a", 1),                        \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ExpectIntEQ(wc_##name##Update(&dgst, NULL, 0), 0);                         \
    ExpectIntEQ(wc_##name##Update(&dgst, (byte*)"a", 1), 0);                   \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_ALT_UPDATE_TEST(type, name)                                     \
do {                                                                           \
    type dgst;                                                                 \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    /* Pass in bad values. */                                                  \
    ExpectIntEQ(wc_##name##_Update(NULL, NULL, 1),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_Update(&dgst, NULL, 1),                            \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_Update(NULL, NULL, 0),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_Update(NULL, (byte*)"a", 1),                       \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ExpectIntEQ(wc_##name##_Update(&dgst, NULL, 0), 0);                        \
    ExpectIntEQ(wc_##name##_Update(&dgst, (byte*)"a", 1), 0);                  \
                                                                               \
    wc_##name##_Free(&dgst);                                                   \
} while (0)

#define DIGEST_UPDATE_ONLY_TEST(type, name)                                    \
    type dgst;                                                                 \
                                                                               \
    wc_Init##name(&dgst);                                                      \
                                                                               \
    /* Pass in bad values. */                                                  \
    wc_##name##Update(NULL, NULL, 1);                                          \
    wc_##name##Update(&dgst, NULL, 1);                                         \
    wc_##name##Update(NULL, NULL, 0);                                          \
    wc_##name##Update(NULL, (byte*)"a", 1);                                    \
                                                                               \
    wc_##name##Update(&dgst, NULL, 0);                                         \
    wc_##name##Update(&dgst, (byte*)"a", 1)

#define DIGEST_FINAL_TEST(type, name, upper)                                   \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
    ExpectIntEQ(wc_##name##Final(&dgst, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG)); \
    ExpectIntEQ(wc_##name##Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
                                                                               \
    /* Test good args. */                                                      \
    ExpectIntEQ(wc_##name##Final(&dgst, hash), 0);                             \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_ALT_FINAL_TEST(type, name, upper)                               \
do {                                                                           \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##_Final(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG)); \
    ExpectIntEQ(wc_##name##_Final(&dgst, NULL),                                \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_Final(NULL, hash), WC_NO_ERR_TRACE(BAD_FUNC_ARG)); \
                                                                               \
    /* Test good args. */                                                      \
    ExpectIntEQ(wc_##name##_Final(&dgst, hash), 0);                            \
                                                                               \
    wc_##name##_Free(&dgst);                                                   \
} while (0)

#define DIGEST_COUNT_FINAL_TEST(type, name, upper)                             \
do {                                                                           \
    type dgst;                                                                 \
    byte hash[WC_##upper##_COUNT * 8];                                         \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##_Final(NULL, NULL, WC_##upper##_COUNT * 8),         \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_Final(&dgst, NULL, WC_##upper##_COUNT * 8),        \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##_Final(NULL, hash, WC_##upper##_COUNT * 8),         \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    /* Test good args. */                                                      \
    ExpectIntEQ(wc_##name##_Final(&dgst, hash, WC_##upper##_COUNT * 8), 0);    \
                                                                               \
    wc_##name##_Free(&dgst);                                                   \
} while (0)

#define DIGEST_FINAL_ONLY_TEST(type, name, upper)                              \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    /* Initialize */                                                           \
    wc_Init##name(&dgst);                                                      \
                                                                               \
    /* Test bad args. */                                                       \
    wc_##name##Final(NULL, NULL);                                              \
    wc_##name##Final(&dgst, NULL);                                             \
    wc_##name##Final(NULL, hash);                                              \
                                                                               \
    /* Test good args. */                                                      \
    wc_##name##Final(&dgst, hash);                                             \

#define DIGEST_FINAL_RAW_TEST(type, name, upper, hashStr)                      \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
    const char* expHash = hashStr;                                             \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##FinalRaw(NULL, NULL),                               \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##FinalRaw(&dgst, NULL),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##FinalRaw(NULL, hash),                               \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    /* Test good args. */                                                      \
    ExpectIntEQ(wc_##name##FinalRaw(&dgst, hash), 0);                          \
    ExpectBufEQ(hash, expHash, WC_##upper##_DIGEST_SIZE);                      \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_KATS_TEST_VARS(type, upper)                                     \
    type dgst;                                                                 \
    testVector dgst_kat[upper##_KAT_CNT];                                      \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
    int i = 0

#define DIGEST_COUNT_KATS_TEST_VARS(type, upper, count)                        \
    type dgst;                                                                 \
    testVector dgst_kat[upper##_KAT_CNT];                                      \
    byte hash[WC_##count##_COUNT * 8];                                         \
    int i = 0

#define DIGEST_KATS_ADD(in, len, out)                                          \
    dgst_kat[i].input = in;                                                    \
    dgst_kat[i].inLen = len;                                                   \
    dgst_kat[i].output = out;                                                  \
    dgst_kat[i].outLen = 0;                                                    \
    i++

#define DIGEST_KATS_TEST(name, upper)                                          \
    (void)i;                                                                   \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    for (i = 0; i < upper##_KAT_CNT; i++) {                                    \
        /* Do KAT. */                                                          \
        ExpectIntEQ(wc_##name##Update(&dgst, (byte*)dgst_kat[i].input,         \
            (word32)dgst_kat[i].inLen), 0);                                    \
        ExpectIntEQ(wc_##name##Final(&dgst, hash), 0);                         \
        ExpectBufEQ(hash, (byte*)dgst_kat[i].output,                           \
            WC_##upper##_DIGEST_SIZE);                                         \
    }                                                                          \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_COUNT_KATS_TEST(name, upper, count)                             \
    (void)i;                                                                   \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    for (i = 0; i < upper##_KAT_CNT; i++) {                                    \
        /* Do KAT. */                                                          \
        ExpectIntEQ(wc_##name##_Update(&dgst, (byte*)dgst_kat[i].input,        \
            (word32)dgst_kat[i].inLen), 0);                                    \
        ExpectIntEQ(wc_##name##_Final(&dgst, hash, WC_##count##_COUNT * 8),    \
            0);                                                                \
        ExpectBufEQ(hash, (byte*)dgst_kat[i].output,                           \
            WC_##count##_COUNT * 8);                                           \
    }                                                                          \
                                                                               \
    wc_##name##_Free(&dgst)

#define DIGEST_KATS_ONLY_TEST(name, upper)                                     \
do {                                                                           \
    (void)i;                                                                   \
                                                                               \
    /* Initialize */                                                           \
    wc_Init##name(&dgst);                                                      \
                                                                               \
    for (i = 0; i < upper##_KAT_CNT; i++) {                                    \
        /* Do KAT. */                                                          \
        wc_##name##Update(&dgst, (byte*)dgst_kat[i].input,                     \
            (word32)dgst_kat[i].inLen);                                        \
        wc_##name##Final(&dgst, hash);                                         \
        ExpectBufEQ(hash, (byte*)dgst_kat[i].output,                           \
            WC_##upper##_DIGEST_SIZE);                                         \
    }                                                                          \
} while (0)

#define DIGEST_OTHER_TEST(type, name, upper, hashStr)                          \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE + 1];                                   \
    byte data[WC_##upper##_DIGEST_SIZE * 8 + 1];                               \
    int dataLen = WC_##upper##_DIGEST_SIZE * 8;                                \
    const char* expHash = hashStr;                                             \
    int i;                                                                     \
    int j;                                                                     \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Unaligned input and output buffer. */                                   \
    ExpectIntEQ(wc_##name##Update(&dgst, data + 1, dataLen), 0);               \
    ExpectIntEQ(wc_##name##Final(&dgst, hash + 1), 0);                         \
    ExpectBufEQ(hash + 1, (byte*)expHash, WC_##upper##_DIGEST_SIZE);           \
                                                                               \
    /* Test that empty updates work. */                                        \
    ExpectIntEQ(wc_##name##Update(&dgst, NULL, 0), 0);                         \
    ExpectIntEQ(wc_##name##Update(&dgst, (byte*)"", 0), 0);                    \
    ExpectIntEQ(wc_##name##Update(&dgst, data, dataLen), 0);                   \
    ExpectIntEQ(wc_##name##Final(&dgst, hash), 0);                             \
    ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_DIGEST_SIZE);               \
                                                                               \
    /* Ensure chunking works. */                                               \
    for (i = 1; i < dataLen; i++) {                                            \
        for (j = 0; j < dataLen; j += i) {                                     \
             int len = dataLen - j;                                            \
             if (i < len)                                                      \
                 len = i;                                                      \
             ExpectIntEQ(wc_##name##Update(&dgst, data + j, len), 0);          \
        }                                                                      \
        ExpectIntEQ(wc_##name##Final(&dgst, hash), 0);                         \
        ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_DIGEST_SIZE);           \
    }                                                                          \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_ALT_OTHER_TEST(type, name, upper, hashStr)                      \
do {                                                                           \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE + 1];                                   \
    byte data[WC_##upper##_DIGEST_SIZE * 8 + 1];                               \
    int dataLen = WC_##upper##_DIGEST_SIZE * 8;                                \
    const char* expHash = hashStr;                                             \
    int i;                                                                     \
    int j;                                                                     \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    /* Unaligned input and output buffer. */                                   \
    ExpectIntEQ(wc_##name##_Update(&dgst, data + 1, dataLen), 0);              \
    ExpectIntEQ(wc_##name##_Final(&dgst, hash + 1), 0);                        \
    ExpectBufEQ(hash + 1, (byte*)expHash, WC_##upper##_DIGEST_SIZE);           \
                                                                               \
    /* Test that empty updates work. */                                        \
    ExpectIntEQ(wc_##name##_Update(&dgst, NULL, 0), 0);                        \
    ExpectIntEQ(wc_##name##_Update(&dgst, (byte*)"", 0), 0);                   \
    ExpectIntEQ(wc_##name##_Update(&dgst, data, dataLen), 0);                  \
    ExpectIntEQ(wc_##name##_Final(&dgst, hash), 0);                            \
    ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_DIGEST_SIZE);               \
                                                                               \
    /* Ensure chunking works. */                                               \
    for (i = 1; i < dataLen; i++) {                                            \
        for (j = 0; j < dataLen; j += i) {                                     \
             int len = dataLen - j;                                            \
             if (i < len)                                                      \
                 len = i;                                                      \
             ExpectIntEQ(wc_##name##_Update(&dgst, data + j, len), 0);         \
        }                                                                      \
        ExpectIntEQ(wc_##name##_Final(&dgst, hash), 0);                        \
        ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_DIGEST_SIZE);           \
    }                                                                          \
                                                                               \
    wc_##name##_Free(&dgst);                                                   \
} while (0)

#define DIGEST_COUNT_OTHER_TEST(type, name, upper, hashStr)                    \
do {                                                                           \
    type dgst;                                                                 \
    byte hash[WC_##upper##_COUNT * 8 + 1];                                     \
    byte data[WC_##upper##_COUNT * 8 * 8 + 1];                                 \
    int dataLen = WC_##upper##_COUNT * 8 * 8;                                  \
    const char* expHash = hashStr;                                             \
    int i;                                                                     \
    int j;                                                                     \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    /* Initialize */                                                           \
    ExpectIntEQ(wc_Init##name(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    /* Unaligned input and output buffer. */                                   \
    ExpectIntEQ(wc_##name##_Update(&dgst, data + 1, dataLen), 0);              \
    ExpectIntEQ(wc_##name##_Final(&dgst, hash + 1, WC_##upper##_COUNT * 8),    \
        0);                                                                    \
    ExpectBufEQ(hash + 1, (byte*)expHash, WC_##upper##_COUNT * 8);             \
                                                                               \
    /* Test that empty updates work. */                                        \
    ExpectIntEQ(wc_##name##_Update(&dgst, NULL, 0), 0);                        \
    ExpectIntEQ(wc_##name##_Update(&dgst, (byte*)"", 0), 0);                   \
    ExpectIntEQ(wc_##name##_Update(&dgst, data, dataLen), 0);                  \
    ExpectIntEQ(wc_##name##_Final(&dgst, hash, WC_##upper##_COUNT * 8), 0);    \
    ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_COUNT * 8);                 \
                                                                               \
    /* Ensure chunking works. */                                               \
    for (i = 1; i < dataLen; i++) {                                            \
        for (j = 0; j < dataLen; j += i) {                                     \
             int len = dataLen - j;                                            \
             if (i < len)                                                      \
                 len = i;                                                      \
             ExpectIntEQ(wc_##name##_Update(&dgst, data + j, len), 0);         \
        }                                                                      \
        ExpectIntEQ(wc_##name##_Final(&dgst, hash, WC_##upper##_COUNT * 8),    \
            0);                                                                \
        ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_COUNT * 8);             \
    }                                                                          \
                                                                               \
    wc_##name##_Free(&dgst);                                                   \
} while (0)

#define DIGEST_OTHER_ONLY_TEST(type, name, upper, hashStr)                     \
do {                                                                           \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE + 1];                                   \
    byte data[WC_##upper##_DIGEST_SIZE * 8 + 1];                               \
    int dataLen = WC_##upper##_DIGEST_SIZE * 8;                                \
    const char* expHash = hashStr;                                             \
    int i;                                                                     \
    int j;                                                                     \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    /* Initialize */                                                           \
    wc_Init##name(&dgst);                                                      \
                                                                               \
    /* Unaligned input and output buffer. */                                   \
    wc_##name##Update(&dgst, data + 1, dataLen);                               \
    wc_##name##Final(&dgst, hash + 1);                                         \
    ExpectBufEQ(hash + 1, (byte*)expHash, WC_##upper##_DIGEST_SIZE);           \
                                                                               \
    /* Test that empty updates work. */                                        \
    wc_##name##Update(&dgst, NULL, 0);                                         \
    wc_##name##Update(&dgst, (byte*)"", 0);                                    \
    wc_##name##Update(&dgst, data, dataLen);                                   \
    wc_##name##Final(&dgst, hash);                                             \
    ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_DIGEST_SIZE);               \
                                                                               \
    /* Ensure chunking works. */                                               \
    for (i = 1; i < dataLen; i++) {                                            \
        for (j = 0; j < dataLen; j += i) {                                     \
             int len = dataLen - j;                                            \
             if (i < len)                                                      \
                 len = i;                                                      \
             wc_##name##Update(&dgst, data + j, len);                          \
        }                                                                      \
        wc_##name##Final(&dgst, hash);                                         \
        ExpectBufEQ(hash, (byte*)expHash, WC_##upper##_DIGEST_SIZE);           \
    }                                                                          \
} while (0)

#define DIGEST_COPY_TEST(type, name, upper, emptyHashStr, abcHashStr)          \
    type src;                                                                  \
    type dst;                                                                  \
    byte hashSrc[WC_##upper##_DIGEST_SIZE];                                    \
    byte hashDst[WC_##upper##_DIGEST_SIZE];                                    \
    const char* emptyHash = emptyHashStr;                                      \
    const char* abcHash = abcHashStr;                                          \
    byte data[WC_##upper##_BLOCK_SIZE];                                        \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    XMEMSET(&src, 0, sizeof(src));                                             \
    XMEMSET(&dst, 0, sizeof(dst));                                             \
    ExpectIntEQ(wc_Init##name(&src), 0);                                       \
                                                                               \
    /* Tests bad params. */                                                    \
    ExpectIntEQ(wc_##name##Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));   \
    ExpectIntEQ(wc_##name##Copy(&src, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));   \
    ExpectIntEQ(wc_##name##Copy(NULL, &dst), WC_NO_ERR_TRACE(BAD_FUNC_ARG));   \
                                                                               \
    /* Test copy works. */                                                     \
    ExpectIntEQ(wc_##name##Copy(&src, &dst), 0);                               \
    ExpectIntEQ(wc_##name##Final(&src, hashSrc), 0);                           \
    ExpectIntEQ(wc_##name##Final(&dst, hashDst), 0);                           \
    ExpectBufEQ(hashSrc, emptyHash, WC_##upper##_DIGEST_SIZE);                 \
    ExpectBufEQ(hashDst, emptyHash, WC_##upper##_DIGEST_SIZE);                 \
    wc_##name##Free(&dst);                                                     \
                                                                               \
    /* Test buffered data is copied. */                                        \
    ExpectIntEQ(wc_##name##Update(&src, (byte*)"abc", 3), 0);                  \
    ExpectIntEQ(wc_##name##Copy(&src, &dst), 0);                               \
    ExpectIntEQ(wc_##name##Final(&src, hashSrc), 0);                           \
    ExpectIntEQ(wc_##name##Final(&dst, hashDst), 0);                           \
    ExpectBufEQ(hashSrc, abcHash, WC_##upper##_DIGEST_SIZE);                   \
    ExpectBufEQ(hashDst, abcHash, WC_##upper##_DIGEST_SIZE);                   \
    wc_##name##Free(&dst);                                                     \
                                                                               \
    /* Test count of length is copied. */                                      \
    ExpectIntEQ(wc_##name##Update(&src, data, sizeof(data)), 0);               \
    ExpectIntEQ(wc_##name##Copy(&src, &dst), 0);                               \
    ExpectIntEQ(wc_##name##Final(&src, hashSrc), 0);                           \
    ExpectIntEQ(wc_##name##Final(&dst, hashDst), 0);                           \
    ExpectBufEQ(hashSrc, hashDst, WC_##upper##_DIGEST_SIZE);                   \
    wc_##name##Free(&dst);                                                     \
                                                                               \
    wc_##name##Free(&src)

#define DIGEST_ALT_COPY_TEST(type, name, upper, emptyHashStr, abcHashStr)      \
do {                                                                           \
    type src;                                                                  \
    type dst;                                                                  \
    byte hashSrc[WC_##upper##_DIGEST_SIZE];                                    \
    byte hashDst[WC_##upper##_DIGEST_SIZE];                                    \
    const char* emptyHash = emptyHashStr;                                      \
    const char* abcHash = abcHashStr;                                          \
    byte data[WC_##upper##_BLOCK_SIZE];                                        \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
    XMEMSET(&src, 0, sizeof(src));                                             \
                                                                               \
    ExpectIntEQ(wc_Init##name(&src, HEAP_HINT, INVALID_DEVID), 0);             \
    XMEMSET(&dst, 0, sizeof(dst));                                             \
                                                                               \
    ExpectIntEQ(wc_##name##_Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
    ExpectIntEQ(wc_##name##_Copy(&src, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
    ExpectIntEQ(wc_##name##_Copy(NULL, &dst), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
                                                                               \
    /* Test copy works. */                                                     \
    ExpectIntEQ(wc_##name##_Copy(&src, &dst), 0);                              \
    ExpectIntEQ(wc_##name##_Final(&src, hashSrc), 0);                          \
    ExpectIntEQ(wc_##name##_Final(&dst, hashDst), 0);                          \
    ExpectBufEQ(hashSrc, emptyHash, WC_##upper##_DIGEST_SIZE);                 \
    ExpectBufEQ(hashDst, emptyHash, WC_##upper##_DIGEST_SIZE);                 \
    wc_##name##_Free(&dst);                                                    \
                                                                               \
    /* Test buffered data is copied. */                                        \
    ExpectIntEQ(wc_##name##_Update(&src, (byte*)"abc", 3), 0);                 \
    ExpectIntEQ(wc_##name##_Copy(&src, &dst), 0);                              \
    ExpectIntEQ(wc_##name##_Final(&src, hashSrc), 0);                          \
    ExpectIntEQ(wc_##name##_Final(&dst, hashDst), 0);                          \
    ExpectBufEQ(hashSrc, abcHash, WC_##upper##_DIGEST_SIZE);                   \
    ExpectBufEQ(hashDst, abcHash, WC_##upper##_DIGEST_SIZE);                   \
    wc_##name##_Free(&dst);                                                    \
                                                                               \
    /* Test count of length is copied. */                                      \
    ExpectIntEQ(wc_##name##_Update(&src, data, sizeof(data)), 0);              \
    ExpectIntEQ(wc_##name##_Copy(&src, &dst), 0);                              \
    ExpectIntEQ(wc_##name##_Final(&src, hashSrc), 0);                          \
    ExpectIntEQ(wc_##name##_Final(&dst, hashDst), 0);                          \
    ExpectBufEQ(hashSrc, hashDst, WC_##upper##_DIGEST_SIZE);                   \
    wc_##name##_Free(&dst);                                                    \
                                                                               \
    wc_##name##_Free(&src);                                                    \
} while (0)

#define DIGEST_COUNT_COPY_TEST(type, name, upper, emptyHashStr, abcHashStr)    \
do {                                                                           \
    type src;                                                                  \
    type dst;                                                                  \
    byte hashSrc[WC_##upper##_COUNT * 8];                                      \
    byte hashDst[WC_##upper##_COUNT * 8];                                      \
    const char* emptyHash = emptyHashStr;                                      \
    const char* abcHash = abcHashStr;                                          \
    byte data[WC_##upper##_BLOCK_SIZE];                                        \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
    XMEMSET(&src, 0, sizeof(src));                                              \
    XMEMSET(&dst, 0, sizeof(dst));                                              \
                                                                               \
    ExpectIntEQ(wc_Init##name(&src, HEAP_HINT, INVALID_DEVID), 0);             \
    XMEMSET(&dst, 0, sizeof(dst));                                             \
                                                                               \
    ExpectIntEQ(wc_##name##_Copy(NULL, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
    ExpectIntEQ(wc_##name##_Copy(&src, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
    ExpectIntEQ(wc_##name##_Copy(NULL, &dst), WC_NO_ERR_TRACE(BAD_FUNC_ARG));  \
                                                                               \
    /* Test copy works. */                                                     \
    ExpectIntEQ(wc_##name##_Copy(&src, &dst), 0);                              \
    ExpectIntEQ(wc_##name##_Final(&src, hashSrc, WC_##upper##_COUNT * 8), 0);  \
    ExpectIntEQ(wc_##name##_Final(&dst, hashDst, WC_##upper##_COUNT * 8), 0);  \
    ExpectBufEQ(hashSrc, emptyHash, WC_##upper##_COUNT * 8);                   \
    ExpectBufEQ(hashDst, emptyHash, WC_##upper##_COUNT * 8);                   \
    wc_##name##_Free(&src);                                                    \
                                                                               \
    /* Test buffered data is copied. */                                        \
    ExpectIntEQ(wc_##name##_Update(&src, (byte*)"abc", 3), 0);                 \
    ExpectIntEQ(wc_##name##_Copy(&src, &dst), 0);                              \
    ExpectIntEQ(wc_##name##_Final(&src, hashSrc, WC_##upper##_COUNT * 8), 0);  \
    ExpectIntEQ(wc_##name##_Final(&dst, hashDst, WC_##upper##_COUNT * 8), 0);  \
    ExpectBufEQ(hashSrc, abcHash, WC_##upper##_COUNT * 8);                     \
    ExpectBufEQ(hashDst, abcHash, WC_##upper##_COUNT * 8);                     \
    wc_##name##_Free(&src);                                                    \
                                                                               \
    /* Test count of length is copied. */                                      \
    ExpectIntEQ(wc_##name##_Update(&src, data, sizeof(data)), 0);              \
    ExpectIntEQ(wc_##name##_Copy(&src, &dst), 0);                              \
    ExpectIntEQ(wc_##name##_Final(&src, hashSrc, WC_##upper##_COUNT * 8), 0);  \
    ExpectIntEQ(wc_##name##_Final(&dst, hashDst, WC_##upper##_COUNT * 8), 0);  \
    ExpectBufEQ(hashSrc, hashDst, WC_##upper##_COUNT * 8);                     \
    wc_##name##_Free(&dst);                                                    \
                                                                               \
    wc_##name##_Free(&src);                                                    \
} while (0)

#define DIGEST_GET_HASH_TEST(type, name, upper, emptyHashStr, abcHashStr)      \
    type dgst;                                                                 \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
    const char* emptyHash = emptyHashStr;                                      \
    const char* abcHash = abcHashStr;                                          \
                                                                               \
    XMEMSET(&dgst, 0, sizeof(dgst));                                           \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    ExpectIntEQ(wc_##name##GetHash(NULL, NULL),                                \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##GetHash(&dgst, NULL),                               \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##GetHash(NULL, hash),                                \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ExpectIntEQ(wc_##name##GetHash(&dgst, hash), 0);                           \
    ExpectBufEQ(hash, emptyHash, WC_##upper##_DIGEST_SIZE);                    \
    /* Test that the hash state hasn't been modified. */                       \
    ExpectIntEQ(wc_##name##Update(&dgst, (byte*)"abc", 3), 0);                 \
    ExpectIntEQ(wc_##name##GetHash(&dgst, hash), 0);                           \
    ExpectBufEQ(hash, abcHash, WC_##upper##_DIGEST_SIZE);                      \
                                                                               \
    wc_##name##Free(&dgst)

#ifdef LITTLE_ENDIAN_ORDER

#define DIGEST_TRANSFORM_TEST(type, name, upper, abcBlockStr, abcHashStr)      \
    type dgst;                                                                 \
    const char* abc##name##Data = abcBlockStr;                                 \
    const char* abcHash = abcHashStr;                                          \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##Transform(NULL, NULL),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(&dgst, NULL),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(NULL, (byte*)abc##name##Data),            \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ExpectIntEQ(wc_##name##Transform(&dgst, (byte*)abc##name##Data), 0);       \
    ExpectBufEQ((byte*)dgst.digest, (byte*)abcHash, WC_##upper##_DIGEST_SIZE); \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_TRANSFORM_FINAL_RAW_TEST(type, name, upper, abcBlockStr,        \
                                        abcHashStr)                            \
    type dgst;                                                                 \
    const char* abc##name##Data = abcBlockStr;                                 \
    const char* abcHash = abcHashStr;                                          \
    byte abcData[WC_##upper##_BLOCK_SIZE];                                     \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    XMEMCPY(abcData, abc##name##Data, WC_##upper##_BLOCK_SIZE);                \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##Transform(NULL, NULL),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(&dgst, NULL),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(NULL, (byte*)abc##name##Data),            \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ExpectIntEQ(wc_##name##Transform(&dgst, (byte*)abcData), 0);               \
    ExpectIntEQ(wc_##name##FinalRaw(&dgst, hash), 0);                          \
    ExpectBufEQ(hash, (byte*)abcHash, WC_##upper##_DIGEST_SIZE);               \
                                                                               \
    wc_##name##Free(&dgst)

#else

#define DIGEST_TRANSFORM_TEST(type, name, upper, abcBlockStr, abcHashStr)      \
    type dgst;                                                                 \
    const char* abc##name##Data = abcBlockStr;                                 \
    const char* abcHash = abcHashStr;                                          \
    char abc##name##DataBE[WC_##upper##_BLOCK_SIZE];                           \
    char abcHashBE[WC_##upper##_DIGEST_SIZE];                                  \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##Transform(NULL, NULL),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(&dgst, NULL),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(NULL, (byte*)abc##name##Data),            \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ByteReverseWords((word32*)abc##name##DataBE, (word32*)abc##name##Data,     \
        WC_##upper##_BLOCK_SIZE);                                              \
    ByteReverseWords((word32*)abcHashBE, (word32*)abcHash,                     \
        WC_##upper##_DIGEST_SIZE);                                             \
    ExpectIntEQ(wc_##name##Transform(&dgst, (byte*)abc##name##DataBE), 0);     \
    ExpectBufEQ((byte*)dgst.digest, (byte*)abcHashBE,                          \
        WC_##upper##_DIGEST_SIZE);                                             \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_TRANSFORM_FINAL_RAW_TEST(type, name, upper, abcBlockStr,        \
                                        abcHashStr)                            \
    type dgst;                                                                 \
    const char* abc##name##Data = abcBlockStr;                                 \
    const char* abcHash = abcHashStr;                                          \
    char abc##name##DataBE[WC_##upper##_BLOCK_SIZE];                           \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##Transform(NULL, NULL),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(&dgst, NULL),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(NULL, (byte*)abc##name##Data),            \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ByteReverseWords((word32*)abc##name##DataBE, (word32*)abc##name##Data,     \
        WC_##upper##_BLOCK_SIZE);                                              \
    ExpectIntEQ(wc_##name##Transform(&dgst, (byte*)abc##name##DataBE), 0);     \
    ExpectIntEQ(wc_##name##FinalRaw(&dgst, hash), 0);                          \
    ExpectBufEQ(hash, (byte*)abcHash, WC_##upper##_DIGEST_SIZE);               \
                                                                               \
    wc_##name##Free(&dgst)

#endif

#define DIGEST_TRANSFORM_FINAL_RAW_ALL_TEST(type, name, upper, abcBlockStr,    \
                                            abcHashStr)                        \
    type dgst;                                                                 \
    const char* abc##name##Data = abcBlockStr;                                 \
    const char* abcHash = abcHashStr;                                          \
    byte abcData[WC_##upper##_BLOCK_SIZE];                                     \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    XMEMCPY(abcData, abc##name##Data, WC_##upper##_BLOCK_SIZE);                \
                                                                               \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Test bad args. */                                                       \
    ExpectIntEQ(wc_##name##Transform(NULL, NULL),                              \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(&dgst, NULL),                             \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Transform(NULL, (byte*)abc##name##Data),            \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
                                                                               \
    ExpectIntEQ(wc_##name##Transform(&dgst, (byte*)abcData), 0);               \
    ExpectIntEQ(wc_##name##FinalRaw(&dgst, hash), 0);                          \
    ExpectBufEQ(hash, (byte*)abcHash, WC_##upper##_DIGEST_SIZE);               \
                                                                               \
    wc_##name##Free(&dgst)

#define DIGEST_FLAGS_TEST(type, name)                                          \
    type dgst;                                                                 \
    type dgst_copy;                                                            \
    word32 flags;                                                              \
                                                                               \
    XMEMSET(&dgst, 0, sizeof(dgst));                                           \
    XMEMSET(&dgst_copy, 0, sizeof(dgst_copy));                                 \
    ExpectIntEQ(wc_Init##name(&dgst), 0);                                      \
                                                                               \
    /* Do nothing. */                                                          \
    ExpectIntEQ(wc_##name##GetFlags(NULL, NULL), 0);                           \
    ExpectIntEQ(wc_##name##GetFlags(&dgst, NULL), 0);                          \
    ExpectIntEQ(wc_##name##GetFlags(NULL, &flags), 0);                         \
    ExpectIntEQ(wc_##name##SetFlags(NULL, 1), 0);                              \
                                                                               \
    ExpectIntEQ(wc_##name##GetFlags(&dgst, &flags), 0);                        \
    ExpectIntEQ(flags, 0);                                                     \
                                                                               \
    ExpectIntEQ(wc_##name##Copy(&dgst, &dgst_copy), 0);                        \
    ExpectIntEQ(wc_##name##GetFlags(&dgst, &flags), 0);                        \
    ExpectIntEQ(flags, 0);                                                     \
    ExpectIntEQ(wc_##name##GetFlags(&dgst_copy, &flags), 0);                   \
    ExpectIntEQ(flags, WC_HASH_FLAG_ISCOPY);                                   \
                                                                               \
    ExpectIntEQ(wc_##name##SetFlags(&dgst, WC_HASH_FLAG_WILLCOPY), 0);         \
    ExpectIntEQ(wc_##name##GetFlags(&dgst, &flags), 0);                        \
    ExpectIntEQ(flags, WC_HASH_FLAG_WILLCOPY);                                 \
    ExpectIntEQ(wc_##name##SetFlags(&dgst, 0), 0);                             \
                                                                               \
    wc_##name##Free(&dgst_copy);                                               \
    wc_##name##Free(&dgst)

#define DIGEST_ALT_FLAGS_TEST(type, name, inst)                                \
    type dgst;                                                                 \
    type dgst_copy;                                                            \
    word32 flags;                                                              \
                                                                               \
    XMEMSET(&dgst, 0, sizeof(dgst));                                           \
    XMEMSET(&dgst_copy, 0, sizeof(dgst_copy));                                 \
    ExpectIntEQ(wc_Init##inst(&dgst, HEAP_HINT, INVALID_DEVID), 0);            \
                                                                               \
    /* Do nothing. */                                                          \
    ExpectIntEQ(wc_##name##_GetFlags(NULL, NULL), 0);                          \
    ExpectIntEQ(wc_##name##_GetFlags(&dgst, NULL), 0);                         \
    ExpectIntEQ(wc_##name##_GetFlags(NULL, &flags), 0);                        \
    ExpectIntEQ(wc_##name##_SetFlags(NULL, 1), 0);                             \
                                                                               \
    ExpectIntEQ(wc_##name##_GetFlags(&dgst, &flags), 0);                       \
    ExpectIntEQ(flags, 0);                                                     \
                                                                               \
    ExpectIntEQ(wc_##inst##_Copy(&dgst, &dgst_copy), 0);                       \
    ExpectIntEQ(wc_##name##_GetFlags(&dgst, &flags), 0);                       \
    ExpectIntEQ(flags, 0);                                                     \
    ExpectIntEQ(wc_##name##_GetFlags(&dgst_copy, &flags), 0);                  \
    ExpectIntEQ(flags, WC_HASH_FLAG_ISCOPY);                                   \
                                                                               \
    ExpectIntEQ(wc_##name##_SetFlags(&dgst, 1), 0);                            \
    ExpectIntEQ(wc_##name##_GetFlags(&dgst, &flags), 0);                       \
    ExpectIntEQ(flags, 1);                                                     \
    ExpectIntEQ(wc_##name##_SetFlags(&dgst, 0), 0);                            \
                                                                               \
    wc_##inst##_Free(&dgst_copy);                                              \
    wc_##inst##_Free(&dgst)

#define DIGEST_HASH_TEST(name, upper)                                          \
do {                                                                           \
    byte data[WC_##upper##_BLOCK_SIZE];                                        \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    /* Invalid parameters. */                                                  \
    ExpectIntEQ(wc_##name##Hash(NULL, sizeof(data), hash),                     \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Hash(data, sizeof(data), NULL),                     \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Hash_ex(NULL, sizeof(data), hash, HEAP_HINT,        \
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));                        \
    ExpectIntEQ(wc_##name##Hash_ex(data, sizeof(data), NULL, HEAP_HINT,        \
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));                        \
                                                                               \
    /* Valid parameters. */                                                    \
    ExpectIntEQ(wc_##name##Hash(data, sizeof(data), hash), 0);                 \
    ExpectIntEQ(wc_##name##Hash_ex(data, sizeof(data), hash, HEAP_HINT,        \
        INVALID_DEVID), 0);                                                    \
} while (0)

#define DIGEST_COUNT_HASH_TEST(name, upper)                                    \
do {                                                                           \
    byte data[WC_##upper##_COUNT * 8];                                         \
    byte hash[WC_##upper##_COUNT * 8];                                         \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    /* Invalid parameters. */                                                  \
    ExpectIntEQ(wc_##name##Hash(NULL, sizeof(data), hash),                     \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Hash(data, sizeof(data), NULL),                     \
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                                        \
    ExpectIntEQ(wc_##name##Hash_ex(NULL, sizeof(data), hash, HEAP_HINT,        \
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));                        \
    ExpectIntEQ(wc_##name##Hash_ex(data, sizeof(data), NULL, HEAP_HINT,        \
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));                        \
                                                                               \
    /* Valid parameters. */                                                    \
    ExpectIntEQ(wc_##name##Hash(data, sizeof(data), hash), 0);                 \
    ExpectIntEQ(wc_##name##Hash_ex(data, sizeof(data), hash, HEAP_HINT,        \
        INVALID_DEVID), 0);                                                    \
} while (0)

#define DIGEST_HASH_ONLY_TEST(name, upper)                                     \
    byte data[WC_##upper##_BLOCK_SIZE];                                        \
    byte hash[WC_##upper##_DIGEST_SIZE];                                       \
                                                                               \
    XMEMSET(data, 0xa5, sizeof(data));                                         \
                                                                               \
    /* Invalid parameters. */                                                  \
    ExpectIntEQ(wc_##name##Hash(NULL, sizeof(data), hash), 0);                 \
    ExpectIntEQ(wc_##name##Hash(data, sizeof(data), NULL), 0);                 \
                                                                               \
    /* Valid parameters. */                                                    \
    ExpectIntEQ(wc_##name##Hash(data, sizeof(data), hash), 0)

