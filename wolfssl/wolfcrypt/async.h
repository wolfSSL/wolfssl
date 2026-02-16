/* async.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WOLFSSL_ASYNC_H
#define WOLFSSL_ASYNC_H

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_ASYNC_CRYPT

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wolfevent.h>
#ifdef HAVE_CAVIUM
    #include <wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h>
#elif defined(HAVE_INTEL_QA)
    #include <wolfssl/wolfcrypt/port/intel/quickassist.h>
#endif


struct WC_ASYNC_DEV;


/* Asynchronous crypto using software */
#ifdef WOLFSSL_ASYNC_CRYPT_SW
    enum WC_ASYNC_SW_TYPE {
        ASYNC_SW_NONE             = 0,
#ifdef HAVE_ECC
        ASYNC_SW_ECC_MAKE         = 1,
    #ifdef HAVE_ECC_SIGN
        ASYNC_SW_ECC_SIGN         = 2,
    #endif
    #ifdef HAVE_ECC_VERIFY
        ASYNC_SW_ECC_VERIFY       = 3,
    #endif
    #ifdef HAVE_ECC_DHE
        ASYNC_SW_ECC_SHARED_SEC   = 4,
    #endif
#endif /* HAVE_ECC */
#ifndef NO_RSA
    #ifdef WOLFSSL_KEY_GEN
        ASYNC_SW_RSA_MAKE         = 5,
    #endif
        ASYNC_SW_RSA_FUNC         = 6,
#endif /* !NO_RSA */
#ifndef NO_DH
        ASYNC_SW_DH_AGREE         = 7,
        ASYNC_SW_DH_GEN           = 8,
#endif /* !NO_DH */
#ifndef NO_AES
        ASYNC_SW_AES_CBC_ENCRYPT  = 9,
    #ifdef HAVE_AES_DECRYPT
        ASYNC_SW_AES_CBC_DECRYPT  = 10,
    #endif
    #ifdef HAVE_AESGCM
        ASYNC_SW_AES_GCM_ENCRYPT  = 11,
        #ifdef HAVE_AES_DECRYPT
        ASYNC_SW_AES_GCM_DECRYPT  = 12,
        #endif
    #endif /* HAVE_AESGCM */
#endif /* !NO_AES */
#ifndef NO_DES3
        ASYNC_SW_DES3_CBC_ENCRYPT = 13,
        ASYNC_SW_DES3_CBC_DECRYPT = 14,
#endif /* !NO_DES3 */
#ifdef HAVE_CURVE25519
        ASYNC_SW_X25519_MAKE = 15,
        ASYNC_SW_X25519_SHARED_SEC = 16,
#endif /* HAVE_CURVE25519 */
    };

#ifdef HAVE_ECC
    struct AsyncCryptSwEccMake {
        void* rng; /* WC_RNG */
        void* key; /* ecc_key */
        int curve_id;
        int size;
    };
    struct AsyncCryptSwEccSign {
        const byte* in;
        word32 inSz;
        void* rng; /* WC_RNG */
        void* key; /* ecc_key */
        void* r; /* mp_int */
        void* s; /* mp_int */
    };
    struct AsyncCryptSwEccVerify {
        void* r; /* mp_int */
        void* s; /* mp_int */
        const byte* hash;
        word32 hashlen;
        int* stat;
        void* key; /* ecc_key */
    };
    struct AsyncCryptSwEccSharedSec {
        void* private_key; /* ecc_key */
        void* public_point; /* ecc_point */
        byte* out;
        word32* outLen;
    };
#endif /* HAVE_ECC */
#ifndef NO_RSA
    #ifdef WOLFSSL_KEY_GEN
        struct AsyncCryptSwRsaMake {
            void* key; /* RsaKey */
            void* rng;
            long e;
            int size;
        };
    #endif
    struct AsyncCryptSwRsaFunc {
        const byte* in;
        word32 inSz;
        byte* out;
        word32* outSz;
        int type;
        void* key; /* RsaKey */
        void* rng;
    };
#endif /* !NO_RSA */

#ifndef NO_DH
    struct AsyncCryptSwDhAgree {
        void* key; /* DhKey */
        byte* agree;
        word32* agreeSz;
        const byte* priv;
        word32 privSz;
        const byte* otherPub;
        word32 pubSz;
    };
    struct AsyncCryptSwDhGen {
        void* key; /* DhKey */
        void* rng; /* WC_RNG */
        byte* priv;
        word32* privSz;
        byte* pub;
        word32* pubSz;
    };
#endif /* !NO_DH */

#ifndef NO_AES
    struct AsyncCryptSwAes {
        void* aes; /* Aes */
        byte* out;
        const byte* in;
        word32 sz;
    #ifdef HAVE_AESGCM
        const byte* iv;
        word32 ivSz;
        byte* authTag;
        word32 authTagSz;
        const byte* authIn;
        word32 authInSz;
    #endif
    };
#endif /* !NO_AES */

#ifndef NO_DES3
    struct AsyncCryptSwDes {
        void* des; /* Des */
        byte* out;
        const byte* in;
        word32 sz;
    };
#endif /* !NO_DES3 */

#ifdef HAVE_CURVE25519
    struct AsyncCryptX25519Make {
        void* rng; /* WC_RNG */
        void* key; /* curve25519_key */
        int size;
    };
    struct AsyncCryptX25519SharedSec {
        void* priv; /* curve25519_key */
        void* pub; /* curve25519_key */
        byte* out;
        word32* outLen;
        int endian;
    };
#endif /* HAVE_CURVE25519 */

    #ifdef __CC_ARM
        #pragma push
        #pragma anon_unions
    #endif

    typedef struct WC_ASYNC_SW {
        void* ctx;
    #ifdef HAVE_ANONYMOUS_INLINE_AGGREGATES
        union {
    #endif
    #ifdef HAVE_ECC
            struct AsyncCryptSwEccMake eccMake;
            struct AsyncCryptSwEccSign eccSign;
            struct AsyncCryptSwEccVerify eccVerify;
            struct AsyncCryptSwEccSharedSec eccSharedSec;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        #ifdef WOLFSSL_KEY_GEN
            struct AsyncCryptSwRsaMake rsaMake;
        #endif
            struct AsyncCryptSwRsaFunc rsaFunc;
    #endif /* !NO_RSA */
    #ifndef NO_DH
        struct AsyncCryptSwDhAgree dhAgree;
        struct AsyncCryptSwDhGen dhGen;
    #endif /* !NO_DH */
    #ifndef NO_AES
        struct AsyncCryptSwAes aes;
    #endif /* !NO_AES */
    #ifndef NO_DES3
        struct AsyncCryptSwDes des;
    #endif /* !NO_DES3 */
    #ifdef HAVE_CURVE25519
        struct AsyncCryptX25519Make x25519Make;
        struct AsyncCryptX25519SharedSec x25519SharedSec;
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_ANONYMOUS_INLINE_AGGREGATES
        }; /* union */
    #endif
        byte type; /* enum WC_ASYNC_SW_TYPE */
    } WC_ASYNC_SW;

    #ifdef __CC_ARM
        #pragma pop
    #endif

#endif /* WOLFSSL_ASYNC_CRYPT_SW */

/* Performance tuning options */

/* determine maximum async pending requests */
#ifdef HAVE_CAVIUM
    #define WOLF_ASYNC_MAX_PENDING  CAVIUM_MAX_PENDING
#elif defined(HAVE_INTEL_QA)
    #define WOLF_ASYNC_MAX_PENDING  QAT_MAX_PENDING
#else
    #define WOLF_ASYNC_MAX_PENDING  8

    #ifdef DEBUG_WOLFSSL
        /* Use this to introduce extra delay in simulator at interval */
        #ifndef WOLF_ASYNC_SW_SKIP_MOD
            #define WOLF_ASYNC_SW_SKIP_MOD    (WOLF_ASYNC_MAX_PENDING / 2)
        #endif
    #endif
#endif

/* async thresholds - defaults */
#ifdef WC_ASYNC_THRESH_NONE
    #undef  WC_ASYNC_THRESH_AES_CBC
    #define WC_ASYNC_THRESH_AES_CBC  1

    #undef  WC_ASYNC_THRESH_AES_GCM
    #define WC_ASYNC_THRESH_AES_GCM  1

    #undef  WC_ASYNC_THRESH_DES3_CBC
    #define WC_ASYNC_THRESH_DES3_CBC 1
#else
    #ifndef WC_ASYNC_THRESH_AES_CBC
        #define WC_ASYNC_THRESH_AES_CBC 1024
    #endif
    #ifndef WC_ASYNC_THRESH_AES_GCM
        #define WC_ASYNC_THRESH_AES_GCM 128
    #endif
    #ifndef WC_ASYNC_THRESH_DES3_CBC
        #define WC_ASYNC_THRESH_DES3_CBC 1024
    #endif
#endif /* WC_ASYNC_THRESH_NONE */

/* Overrides to allow disabling async support per algorithm */
#ifndef WC_ASYNC_NO_CRYPT
    #ifndef WC_ASYNC_NO_ARC4
        #define WC_ASYNC_ENABLE_ARC4
    #endif
    #ifndef WC_ASYNC_NO_AES
        #define WC_ASYNC_ENABLE_AES
    #endif
    #ifndef WC_ASYNC_NO_3DES
        #define WC_ASYNC_ENABLE_3DES
    #endif
#endif /* WC_ASYNC_NO_CRYPT */
#ifndef WC_ASYNC_NO_PKI
    #ifndef WC_ASYNC_NO_RSA_KEYGEN
        #define WC_ASYNC_ENABLE_RSA_KEYGEN
    #endif
    #ifndef WC_ASYNC_NO_RSA
        #define WC_ASYNC_ENABLE_RSA
    #endif
    #ifndef WC_ASYNC_NO_ECC
        #define WC_ASYNC_ENABLE_ECC
    #endif
    #ifndef WC_ASYNC_NO_DH
        #define WC_ASYNC_ENABLE_DH
    #endif
    #ifndef WC_ASYNC_NO_X25519
        #define WC_ASYNC_ENABLE_X25519
    #endif
#endif /* WC_ASYNC_NO_PKI */
#ifndef WC_ASYNC_NO_HASH
    #ifndef WC_ASYNC_NO_SHA512
        #define WC_ASYNC_ENABLE_SHA512
    #endif
    #ifndef WC_ASYNC_NO_SHA384
        #define WC_ASYNC_ENABLE_SHA384
    #endif
    #ifndef WC_ASYNC_NO_SHA256
        #define WC_ASYNC_ENABLE_SHA256
    #endif
    #ifndef WC_ASYNC_NO_SHA224
        #define WC_ASYNC_ENABLE_SHA224
    #endif
    #ifndef WC_ASYNC_NO_SHA
        #define WC_ASYNC_ENABLE_SHA
    #endif
    #ifndef WC_ASYNC_NO_MD5
        #define WC_ASYNC_ENABLE_MD5
    #endif
    #ifndef WC_ASYNC_NO_HMAC
        #define WC_ASYNC_ENABLE_HMAC
    #endif
    #ifndef WC_ASYNC_NO_SHA3
        #define WC_ASYNC_ENABLE_SHA3
    #endif
#endif /* WC_ASYNC_NO_HASH */
#ifndef WC_ASYNC_NO_RNG
    #define WC_ASYNC_ENABLE_RNG
#endif


/* async marker values */
#define WOLFSSL_ASYNC_MARKER_INVALID 0x0
#define WOLFSSL_ASYNC_MARKER_ARC4   0xBEEF0001
#define WOLFSSL_ASYNC_MARKER_AES    0xBEEF0002
#define WOLFSSL_ASYNC_MARKER_3DES   0xBEEF0003
#define WOLFSSL_ASYNC_MARKER_RNG    0xBEEF0004
#define WOLFSSL_ASYNC_MARKER_HMAC   0xBEEF0005
#define WOLFSSL_ASYNC_MARKER_RSA    0xBEEF0006
#define WOLFSSL_ASYNC_MARKER_ECC    0xBEEF0007
#define WOLFSSL_ASYNC_MARKER_SHA512 0xBEEF0008
#define WOLFSSL_ASYNC_MARKER_SHA384 0xBEEF0009
#define WOLFSSL_ASYNC_MARKER_SHA256 0xBEEF000A
#define WOLFSSL_ASYNC_MARKER_SHA224 0xBEEF000B
#define WOLFSSL_ASYNC_MARKER_SHA    0xBEEF000C
#define WOLFSSL_ASYNC_MARKER_MD5    0xBEEF000D
#define WOLFSSL_ASYNC_MARKER_DH     0xBEEF000E
#define WOLFSSL_ASYNC_MARKER_SHA3   0xBEEF000F
#define WOLFSSL_ASYNC_MARKER_X25519 0xBEEF0010


/* event flags (bit mask) */
enum WC_ASYNC_FLAGS {
    WC_ASYNC_FLAG_NONE =            0x00000000,

    /* crypto needs called again after WC_PENDING_E */
    WC_ASYNC_FLAG_CALL_AGAIN =      0x00000001,
};

/* async device */
typedef struct WC_ASYNC_DEV {
    word32              marker;  /* async marker */
    void*               heap;

    /* event */
    WOLF_EVENT          event;

    /* context for driver */
#ifdef HAVE_CAVIUM
    CaviumNitroxDev     nitrox;
#elif defined(HAVE_INTEL_QA)
    IntelQaDev          qat;
#elif defined(WOLFSSL_ASYNC_CRYPT_SW)
    WC_ASYNC_SW         sw;
#endif
} WC_ASYNC_DEV;


/* Interfaces */
WOLFSSL_API int wolfAsync_HardwareStart(void);
WOLFSSL_API void wolfAsync_HardwareStop(void);
WOLFSSL_API int wolfAsync_DevOpen(int *devId);
WOLFSSL_API int wolfAsync_DevOpenThread(int *devId, void* threadId);
WOLFSSL_API int wolfAsync_DevCtxInit(WC_ASYNC_DEV* asyncDev, word32 marker,
    void* heap, int devId);
WOLFSSL_API void wolfAsync_DevCtxFree(WC_ASYNC_DEV* asyncDev, word32 marker);
WOLFSSL_API void wolfAsync_DevClose(int *devId);
WOLFSSL_API int wolfAsync_DevCopy(WC_ASYNC_DEV* src, WC_ASYNC_DEV* dst);

WOLFSSL_API int wolfAsync_EventInit(WOLF_EVENT* event,
    enum WOLF_EVENT_TYPE type, void* context, word32 flags);
WOLFSSL_API int wolfAsync_EventWait(WOLF_EVENT* event);
WOLFSSL_API int wolfAsync_EventPoll(WOLF_EVENT* event,
    WOLF_EVENT_FLAG event_flags);
WOLFSSL_API int wolfAsync_EventPop(WOLF_EVENT* event,
    enum WOLF_EVENT_TYPE event_type);
WOLFSSL_API int wolfAsync_EventQueuePush(WOLF_EVENT_QUEUE* queue,
    WOLF_EVENT* event);
WOLFSSL_API int wolfAsync_EventQueuePoll(WOLF_EVENT_QUEUE* queue,
    void* context_filter, WOLF_EVENT** events, int maxEvents,
    WOLF_EVENT_FLAG event_flags, int* eventCount);

WOLFSSL_API int wc_AsyncHandle(WC_ASYNC_DEV* asyncDev,
    WOLF_EVENT_QUEUE* queue, word32 flags);
WOLFSSL_API int wc_AsyncWait(int ret, WC_ASYNC_DEV* asyncDev,
    word32 flags);

WOLFSSL_API int wc_AsyncSleep(word32 ms);

#ifdef WOLFSSL_ASYNC_CRYPT_SW
    WOLFSSL_API int wc_AsyncSwInit(WC_ASYNC_DEV* dev, int type);
#endif

/* Pthread Helpers */
#ifndef WC_NO_ASYNC_THREADING
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>

typedef void* (*AsyncThreadFunc_t) (void *);

#define THREAD_DEFAULT_PRIORITY     (0)
#define THREAD_DEFAULT_POLICY       SCHED_OTHER

WOLFSSL_API int wc_AsyncGetNumberOfCpus(void);
WOLFSSL_API int wc_AsyncThreadCreate(pthread_t *thread,
    AsyncThreadFunc_t function, void* params);
WOLFSSL_API int wc_AsyncThreadCreate_ex(pthread_t *thread,
    word32 priority, int policy,
    AsyncThreadFunc_t function, void* params);
WOLFSSL_API int wc_AsyncThreadBind(pthread_t *thread, word32 logicalCore);
WOLFSSL_API int wc_AsyncThreadStart(pthread_t *thread);
WOLFSSL_API void wc_AsyncThreadExit(void *retval);
WOLFSSL_API int wc_AsyncThreadKill(pthread_t *thread);
WOLFSSL_API int wc_AsyncThreadPrioritySet(pthread_t *thread, word32 priority);
WOLFSSL_API int wc_AsyncThreadSetPolicyAndPriority(pthread_t *thread,
    word32 policy, word32 priority);
WOLFSSL_API int wc_AsyncThreadJoin(pthread_t *thread);
WOLFSSL_API void wc_AsyncThreadYield(void);
WOLFSSL_API pthread_t wc_AsyncThreadId(void);

#endif /* WC_NO_ASYNC_THREADING */

#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_ASYNC_H */
