/* types.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/*!
    \file wolfssl/wolfcrypt/types.h
*/
/*
DESCRIPTION
This library defines the primitive data types and abstraction macros to
decouple library dependencies with standard string, memory and so on.

*/
#ifndef WOLF_CRYPT_TYPES_H
#define WOLF_CRYPT_TYPES_H

    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/wc_port.h>

    #if defined(EXTERNAL_OPTS_OPENVPN) && defined(BUILDING_WOLFSSL)
    #error EXTERNAL_OPTS_OPENVPN should not be defined in compiled wolfssl library files.
    #endif

    #ifdef __APPLE__
        #include <AvailabilityMacros.h>
    #endif

    #ifdef __cplusplus
        extern "C" {
    #endif


    /*
     * This struct is used multiple time by other structs and
     * needs to be defined somewhere that all structs can import
     * (with minimal dependencies).
     */
    #ifdef HAVE_EX_DATA
        #ifdef HAVE_EX_DATA_CLEANUP_HOOKS
        typedef void (*wolfSSL_ex_data_cleanup_routine_t)(void *data);
        #endif
        typedef struct WOLFSSL_CRYPTO_EX_DATA {
            void* ex_data[MAX_EX_DATA];
            #ifdef HAVE_EX_DATA_CLEANUP_HOOKS
            wolfSSL_ex_data_cleanup_routine_t
                ex_data_cleanup_routines[MAX_EX_DATA];
            #endif
        } WOLFSSL_CRYPTO_EX_DATA;
        typedef void (WOLFSSL_CRYPTO_EX_new)(void* p, void* ptr,
                WOLFSSL_CRYPTO_EX_DATA* a, int idx, long argValue, void* arg);
        typedef int  (WOLFSSL_CRYPTO_EX_dup)(WOLFSSL_CRYPTO_EX_DATA* out,
                const WOLFSSL_CRYPTO_EX_DATA* in, void* inPtr, int idx,
                long argV, void* arg);
        typedef void (WOLFSSL_CRYPTO_EX_free)(void* p, void* ptr,
                WOLFSSL_CRYPTO_EX_DATA* a, int idx, long argValue, void* arg);
    #endif

    #if defined(WORDS_BIGENDIAN)
        #define BIG_ENDIAN_ORDER
    #endif

    #ifndef BIG_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif

    #ifndef WOLFSSL_TYPES
        #define WOLFSSL_TYPES
        #ifndef byte
            /* If using C++ C17 or later and getting:
             *   "error: reference to 'byte' is ambiguous", this is caused by
             * cstddef conflict with "std::byte" in
             *   "enum class byte : unsigned char {};".
             * This can occur if the user application is using "std" as the
             * default namespace before including wolfSSL headers.
             * Workarounds: https://github.com/wolfSSL/wolfssl/issues/5400
             */
            typedef unsigned char  byte;
        #endif
            typedef   signed char  sword8;
            typedef unsigned char  word8;
        #ifdef WC_16BIT_CPU
            typedef          int   sword16;
            typedef unsigned int   word16;
            typedef          long  sword32;
            typedef unsigned long  word32;
        #else
            typedef          short sword16;
            typedef unsigned short word16;
            typedef          int   sword32;
            typedef unsigned int   word32;
        #endif
        typedef byte           word24[3];
    #endif


    /* constant pointer to a constant char */
    #ifdef WOLFSSL_NO_CONSTCHARCONST
        typedef const char*       wcchar;
    #else
        typedef const char* const wcchar;
    #endif

    #ifndef WC_BITFIELD
        #ifdef WOLF_C89
            #define WC_BITFIELD unsigned
        #else
            #define WC_BITFIELD byte
        #endif
    #endif

    #ifndef HAVE_ANONYMOUS_INLINE_AGGREGATES
        /* if a version is available, pivot on the version, otherwise guess it's
         * disallowed, subject to override.
         */
        #if !defined(WOLF_C89) && (!defined(__STDC__)                \
            || (!defined(__STDC_VERSION__) && !defined(__cplusplus)) \
            || (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201101L)) \
            || (defined(__cplusplus) && (__cplusplus >= 201103L)))
            #define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
        #endif
    #elif ~(~HAVE_ANONYMOUS_INLINE_AGGREGATES + 1) == 1
        /* forced on with empty value -- remap to 1 */
        #undef HAVE_ANONYMOUS_INLINE_AGGREGATES
        #define HAVE_ANONYMOUS_INLINE_AGGREGATES 1
    #elif HAVE_ANONYMOUS_INLINE_AGGREGATES
        /* forced on with explicit nonzero value -- leave as-is. */
    #else
        /* forced off with explicit zero value -- remap to undef. */
        #undef HAVE_ANONYMOUS_INLINE_AGGREGATES
    #endif

    #ifndef HAVE_EMPTY_AGGREGATES
        /* The C standards don't define empty aggregates, but gcc and clang do.
         * We need to accommodate them for one of the same reasons C++ does --
         * conditionally empty aggregates, e.g. in hash.h.
         */
        #if !defined(WOLF_C89) && defined(__GNUC__) &&  \
                !defined(__STRICT_ANSI__) &&            \
                defined(HAVE_ANONYMOUS_INLINE_AGGREGATES)
            #define HAVE_EMPTY_AGGREGATES 1
        #endif
    #elif ~(~HAVE_EMPTY_AGGREGATES + 1) == 1
        /* forced on with empty value -- remap to 1 */
        #undef HAVE_EMPTY_AGGREGATES
        #define HAVE_EMPTY_AGGREGATES 1
    #elif HAVE_EMPTY_AGGREGATES
        /* forced on with explicit nonzero value -- leave as-is. */
    #else
        /* forced off with explicit zero value -- remap to undef. */
        #undef HAVE_EMPTY_AGGREGATES
    #endif

    #define _WOLF_AGG_DUMMY_MEMBER_HELPER2(a, b, c) a ## b ## c
    #define _WOLF_AGG_DUMMY_MEMBER_HELPER(a, b, c) _WOLF_AGG_DUMMY_MEMBER_HELPER2(a, b, c)
    #ifdef HAVE_EMPTY_AGGREGATES
        /* swallow the semicolon with a zero-sized array (language extension
         * specific to gcc/clang).
         */
        #define WOLF_AGG_DUMMY_MEMBER                                          \
            struct {                                                           \
                PRAGMA_GCC_DIAG_PUSH                                           \
                PRAGMA_GCC("GCC diagnostic ignored \"-Wpedantic\"")            \
                PRAGMA_CLANG_DIAG_PUSH                                         \
                PRAGMA_CLANG("clang diagnostic ignored \"-Wzero-length-array\"") \
                byte _WOLF_AGG_DUMMY_MEMBER_HELPER(_wolf_L, __LINE__, _agg_dummy_member)[0]; \
                PRAGMA_CLANG_DIAG_POP                                          \
                PRAGMA_GCC_DIAG_POP                                            \
            }
    #else
        /* Use a single byte with a constructed name as a dummy member -- these
         * are the standard semantics of an empty structure in C++.
         */
        #define WOLF_AGG_DUMMY_MEMBER char _WOLF_AGG_DUMMY_MEMBER_HELPER(_wolf_L, __LINE__, _agg_dummy_member)
    #endif

    /* helpers for stringifying the expanded value of a macro argument rather
     * than its literal text:
     */
    #define _WC_STRINGIFY_L2(str) #str
    #define WC_STRINGIFY(str) _WC_STRINGIFY_L2(str)

    /* With a true C89-dialect compiler (simulate with gcc -std=c89 -Wall
     * -Wextra -pedantic), a trailing comma on the last value in an enum
     * definition is a syntax error.  We use this macro to accommodate that
     * without disrupting clean flow/syntax when some enum values are
     * preprocessor-gated.
     */
    #if defined(WOLF_C89) || defined(WOLF_NO_TRAILING_ENUM_COMMAS)
        #define _WOLF_ENUM_DUMMY_LAST_ELEMENT_HELPER2(a, b, c, d, e) a ## b ## c ## d ## e
        #define _WOLF_ENUM_DUMMY_LAST_ELEMENT_HELPER(a, b, c, d, e) _WOLF_ENUM_DUMMY_LAST_ELEMENT_HELPER2(a, b, c, d, e)
        #define WOLF_ENUM_DUMMY_LAST_ELEMENT(prefix) _WOLF_ENUM_DUMMY_LAST_ELEMENT_HELPER(_wolf_, prefix, _L, __LINE__, _enum_dummy_last_element)
    #else
        #define WOLF_ENUM_DUMMY_LAST_ELEMENT(prefix) /* null expansion */
    #endif

    /* try to set SIZEOF_LONG or SIZEOF_LONG_LONG if user didn't */
    #if defined(_WIN32) || defined(HAVE_LIMITS_H)
        /* make sure both SIZEOF_LONG_LONG and SIZEOF_LONG are set,
         * otherwise causes issues with CTC_SETTINGS */
        #if !defined(SIZEOF_LONG_LONG) || !defined(SIZEOF_LONG)
            #include <limits.h>
            #if !defined(SIZEOF_LONG) && defined(ULONG_MAX) && \
                    (ULONG_MAX == 0xffffffffUL)
                #define SIZEOF_LONG 4
            #endif
            #if !defined(SIZEOF_LONG_LONG) && defined(ULLONG_MAX) && \
                    (ULLONG_MAX == 0xffffffffffffffffULL)
                #define SIZEOF_LONG_LONG 8
            #endif
        #endif
    #elif !defined(__BCPLUSPLUS__) && !defined(__EMSCRIPTEN__)
        #if !defined(SIZEOF_LONG_LONG) && !defined(SIZEOF_LONG)
            #if (defined(__alpha__) || defined(__ia64__) || \
                defined(_ARCH_PPC64) || defined(__ppc64__) || \
                defined(__x86_64__)  || defined(__s390x__ ) || \
                ((defined(sun) || defined(__sun)) && \
                 (defined(LP64) || defined(_LP64))) || \
                (defined(__riscv_xlen) && (__riscv_xlen == 64)) || \
                defined(__aarch64__) || defined(__mips64) || \
                (defined(__DCC__) && (defined(__LP64) || defined(__LP64__))))
                /* long should be 64bit */
                #define SIZEOF_LONG 8
            #elif defined(__i386__) || defined(__CORTEX_M3__) || defined(__ppc__)
                /* long long should be 64bit */
                #define SIZEOF_LONG_LONG 8
            #endif
         #endif
    #endif

    #if (defined(_MSC_VER) && !defined(WOLFSSL_NOT_WINDOWS_API)) || \
           defined(__BCPLUSPLUS__) || \
           (defined(__WATCOMC__) && defined(__WATCOM_INT64__))
        /* windows types */
        #define WORD64_AVAILABLE
        #define W64LIT(x) x##ui64
        #define SW64LIT(x) x##i64
        typedef          __int64 sword64;
        typedef unsigned __int64 word64;
    #elif defined(__EMSCRIPTEN__)
        #define WORD64_AVAILABLE
        #define W64LIT(x) x##ull
        #define SW64LIT(x) x##ll
        typedef          long long sword64;
        typedef unsigned long long word64;
    #elif defined(SIZEOF_LONG) && SIZEOF_LONG == 8
        #define WORD64_AVAILABLE
        #ifdef WOLF_C89
            #define W64LIT(x) x##UL
            #define SW64LIT(x) x##L
        #else
            #define W64LIT(x) x##ULL
            #define SW64LIT(x) x##LL
        #endif
        typedef          long sword64;
        typedef unsigned long word64;
    #elif defined(SIZEOF_LONG_LONG) && SIZEOF_LONG_LONG == 8
        #define WORD64_AVAILABLE
        #ifdef WOLF_C89
            #define W64LIT(x) x##UL
            #define SW64LIT(x) x##L
        #else
            #define W64LIT(x) x##ULL
            #define SW64LIT(x) x##LL
        #endif
        typedef          long long sword64;
        typedef unsigned long long word64;
    #elif defined(__SIZEOF_LONG_LONG__) && __SIZEOF_LONG_LONG__ == 8
        #define WORD64_AVAILABLE
        #ifdef WOLF_C89
            #define W64LIT(x) x##UL
            #define SW64LIT(x) x##L
        #else
            #define W64LIT(x) x##ULL
            #define SW64LIT(x) x##LL
        #endif
        typedef          long long sword64;
        typedef unsigned long long word64;
    #endif

#if defined(WORD64_AVAILABLE) && !defined(WC_16BIT_CPU)
    /* These platforms have 64-bit CPU registers.  */
    #if (defined(__alpha__) || defined(__ia64__) || defined(_ARCH_PPC64) || \
        (defined(__mips64) && \
         ((defined(_ABI64) && (_MIPS_SIM == _ABI64)) || \
          (defined(_ABIO64) && (_MIPS_SIM == _ABIO64)))) || \
         defined(__x86_64__) || defined(_M_X64)) || \
         defined(__aarch64__) || defined(__sparc64__) || defined(__s390x__ ) || \
        (defined(__riscv_xlen) && (__riscv_xlen == 64)) || defined(_M_ARM64) || \
        defined(__aarch64__) || defined(__ppc64__) || \
        (defined(__DCC__) && (defined(__LP64) || defined(__LP64__)))
        #define WC_64BIT_CPU
    #elif (defined(sun) || defined(__sun)) && \
          (defined(LP64) || defined(_LP64))
        /* LP64 with GNU GCC compiler is reserved for when long int is 64 bits
         * and int uses 32 bits. When using Solaris Studio sparc and __sparc are
         * available for 32 bit detection but __sparc64__ could be missed. This
         * uses LP64 for checking 64 bit CPU arch. */
        #define WC_64BIT_CPU
    #else
        #define WC_32BIT_CPU
    #endif

    #if defined(NO_64BIT)
          typedef word32 wolfssl_word;
          #undef WORD64_AVAILABLE
    #else
        #ifdef WC_64BIT_CPU
          typedef word64 wolfssl_word;
        #else
          typedef word32 wolfssl_word;
          #ifdef WORD64_AVAILABLE
              #define WOLFCRYPT_SLOW_WORD64
          #endif
        #endif
    #endif

#elif defined(WC_16BIT_CPU)
    #ifndef MICROCHIP_PIC24
        #undef WORD64_AVAILABLE
    #endif
        typedef word16 wolfssl_word;
        #define MP_16BIT  /* for mp_int, mp_word needs to be twice as big as \
                           * mp_digit, no 64 bit type so make mp_digit 16 bit */

#else
        #undef WORD64_AVAILABLE
        typedef word32 wolfssl_word;
        #define MP_16BIT  /* for mp_int, mp_word needs to be twice as big as \
                           * mp_digit, no 64 bit type so make mp_digit 16 bit */
#endif

typedef struct w64wrapper {
#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_W64_WRAPPER_TEST)
    word64 n;
#else
    word32 n[2];
#endif /* WORD64_AVAILABLE && WOLFSSL_W64_WRAPPER_TEST */
} w64wrapper;

#ifdef WC_PTR_TYPE /* Allow user supplied type */
    typedef WC_PTR_TYPE wc_ptr_t;
#elif defined(HAVE_UINTPTR_T)
    #include <stdint.h>
    typedef uintptr_t wc_ptr_t;
#else /* fallback to architecture size_t for pointer size */
    #include <stddef.h> /* included for getting size_t type */
    typedef size_t wc_ptr_t;
#endif

    enum {
        WOLFSSL_WORD_SIZE  = sizeof(wolfssl_word),
        WOLFSSL_BIT_SIZE   = 8,
        WOLFSSL_WORD_BITS  = WOLFSSL_WORD_SIZE * WOLFSSL_BIT_SIZE
    };

    #define WOLFSSL_MAX_8BIT  0xffU
    #define WOLFSSL_MAX_16BIT 0xffffU
    #define WOLFSSL_MAX_32BIT 0xffffffffU

    #ifndef WC_DO_NOTHING
        #define WC_DO_NOTHING do {} while (0)
        #ifdef _MSC_VER
            /* disable buggy MSC warning around while(0),
             *"warning C4127: conditional expression is constant"
             */
            #pragma warning(disable: 4127)
        #endif
    #endif

    #if defined(HAVE_FIPS) || defined(HAVE_SELFTEST)
        #define INLINE WC_INLINE
    #endif

    /* set up rotate style */
    #if ((defined(_MSC_VER) && !defined(WOLFSSL_NOT_WINDOWS_API)) || \
        defined(__BCPLUSPLUS__)) && !defined(WOLFSSL_SGX) && !defined(INTIME_RTOS)
        #define INTEL_INTRINSICS
        #define FAST_ROTATE
    #elif defined(__MWERKS__) && TARGET_CPU_PPC
        #define PPC_INTRINSICS
        #define FAST_ROTATE
    #elif defined(__CCRX__)
        #define FAST_ROTATE
    #elif defined(__GNUC__)  && (defined(__i386__) || defined(__x86_64__))
        /* GCC does peephole optimizations which should result in using rotate
           instructions  */
        #define FAST_ROTATE
    #endif

    /* set up thread local storage if available */
    #ifdef HAVE_THREAD_LS
        #if defined(_MSC_VER)
            #define THREAD_LS_T __declspec(thread)
        /* Thread local storage only in FreeRTOS v8.2.1 and higher */
        #elif defined(FREERTOS) || defined(FREERTOS_TCP) || \
                                                         defined(WOLFSSL_ZEPHYR)
            #define THREAD_LS_T
        #else
            #define THREAD_LS_T __thread
        #endif
    #else
        #define THREAD_LS_T
    #endif

    #ifndef FALL_THROUGH
        /* GCC 7 has new switch() fall-through detection */
        #if defined(__GNUC__)
            #if defined(fallthrough)
                #define FALL_THROUGH fallthrough
            #elif ((__GNUC__ > 7) || ((__GNUC__ == 7) && (__GNUC_MINOR__ >= 1)))
                #define FALL_THROUGH ; __attribute__ ((fallthrough))
            #elif defined(__clang__) && defined(__clang_major__) && \
                    (__clang_major__ >= 12)
                #define FALL_THROUGH ; __attribute__ ((fallthrough))
            #endif
        #endif
    #endif /* FALL_THROUGH */
    #if !defined(FALL_THROUGH) || defined(__XC32)
        /* use stub for fall through by default or for Microchip compiler */
        #undef  FALL_THROUGH
        #define FALL_THROUGH
    #endif

    #define XSTR_SIZEOF(x) (sizeof(x) - 1) /* -1 to not count the null char */

    #define XELEM_CNT(x) (sizeof((x))/sizeof(*(x)))

    #define WC_SAFE_SUM_WORD32(in1, in2, out) ((in2) <= 0xffffffffU - (in1) ? \
                ((out) = (in1) + (in2), 1) : ((out) = 0xffffffffU, 0))

    #if defined(HAVE_IO_POOL)
        WOLFSSL_API void* XMALLOC(size_t n, void* heap, int type);
        WOLFSSL_API void* XREALLOC(void *p, size_t n, void* heap, int type);
        WOLFSSL_API void XFREE(void *p, void* heap, int type);
    #elif (defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_INTEL_QA)) || \
          defined(HAVE_INTEL_QA_SYNC)
        #ifndef HAVE_INTEL_QA_SYNC
            #include <wolfssl/wolfcrypt/port/intel/quickassist_mem.h>
            #undef USE_WOLFSSL_MEMORY
            #ifdef WOLFSSL_DEBUG_MEMORY
                #define XMALLOC(s, h, t)     IntelQaMalloc((s), (h), (t), __func__, __LINE__)
                #define XFREE(p, h, t)       IntelQaFree((p), (h), (t), __func__, __LINE__)
                #define XREALLOC(p, n, h, t) IntelQaRealloc((p), (n), (h), (t), __func__, __LINE__)
            #else
                #define XMALLOC(s, h, t)     IntelQaMalloc((s), (h), (t))
                #define XFREE(p, h, t)       IntelQaFree((p), (h), (t))
                #define XREALLOC(p, n, h, t) IntelQaRealloc((p), (n), (h), (t))
            #endif /* WOLFSSL_DEBUG_MEMORY */
        #else
            #include <wolfssl/wolfcrypt/port/intel/quickassist_sync.h>
            #undef USE_WOLFSSL_MEMORY
            #ifdef WOLFSSL_DEBUG_MEMORY
                #define XMALLOC(s, h, t)     wc_CryptoCb_IntelQaMalloc((s), (h), (t), __func__, __LINE__)
                #define XFREE(p, h, t)       wc_CryptoCb_IntelQaFree((p), (h), (t), __func__, __LINE__)
                #define XREALLOC(p, n, h, t) wc_CryptoCb_IntelQaRealloc((p), (n), (h), (t), __func__, __LINE__)
            #else
                #define XMALLOC(s, h, t)     wc_CryptoCb_IntelQaMalloc((s), (h), (t))
                #define XFREE(p, h, t)       wc_CryptoCb_IntelQaFree((p), (h), (t))
                #define XREALLOC(p, n, h, t) wc_CryptoCb_IntelQaRealloc((p), (n), (h), (t))
            #endif /* WOLFSSL_DEBUG_MEMORY */
        #endif
    #elif defined(XMALLOC_USER)
        /* prototypes for user heap override functions */
        #include <stddef.h>  /* for size_t */
        extern void *XMALLOC(size_t n, void* heap, int type);
        extern void *XREALLOC(void *p, size_t n, void* heap, int type);
        extern void XFREE(void *p, void* heap, int type);
    #elif defined(WOLFSSL_MEMORY_LOG)
        #define XMALLOC(n, h, t)        xmalloc(n, h, t, __func__, __FILE__, __LINE__)
        #define XREALLOC(p, n, h, t)    xrealloc(p, n, h, t, __func__,  __FILE__, __LINE__)
        #define XFREE(p, h, t)          xfree(p, h, t, __func__, __FILE__, __LINE__)

        /* prototypes for user heap override functions */
        #include <stddef.h>  /* for size_t */
        #include <stdlib.h>
        WOLFSSL_API void *xmalloc(size_t n, void* heap, int type,
                const char* func, const char* file, unsigned int line);
        WOLFSSL_API void *xrealloc(void *p, size_t n, void* heap, int type,
                const char* func, const char* file, unsigned int line);
        WOLFSSL_API void xfree(void *p, void* heap, int type, const char* func,
                const char* file, unsigned int line);
    #elif defined(XMALLOC_OVERRIDE)
        /* override the XMALLOC, XFREE and XREALLOC macros */
    #elif defined(WOLFSSL_TELIT_M2MB)
        /* Telit M2MB SDK requires use m2mb_os API's, not std malloc/free */
        /* Use of malloc/free will cause CPU reboot */
        #define XMALLOC(s, h, t)     ((void)(h), (void)(t), m2mb_os_malloc((s)))
        #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
            #define XFREE(p, h, t)       m2mb_os_free(xp)
        #else
            #define XFREE(p, h, t)       do { void* xp = (p); if (xp) m2mb_os_free(xp); } while (0)
        #endif
        #define XREALLOC(p, n, h, t) m2mb_os_realloc((p), (n))

    #elif defined(NO_WOLFSSL_MEMORY)
        #ifdef WOLFSSL_NO_MALLOC
            /* this platform does not support heap use */
            #ifdef WOLFSSL_SMALL_STACK
                #error WOLFSSL_SMALL_STACK requires a heap implementation.
            #endif
            #ifndef WC_NO_CONSTRUCTORS
                #define WC_NO_CONSTRUCTORS
            #endif
            #ifdef WOLFSSL_MALLOC_CHECK
                #ifndef NO_STDIO_FILESYSTEM
                #include <stdio.h>
                #endif
                static inline void* malloc_check(size_t sz) {
                    fprintf(stderr, "wolfSSL_malloc failed");
                    return NULL;
                };
                #define XMALLOC(s, h, t)     ((void)(h), (void)(t), malloc_check((s)))
                #define XFREE(p, h, t)       do { (void)(h); (void)(t); } while (0)
                #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), NULL)
            #else
                #define XMALLOC(s, h, t)     ((void)(s), (void)(h), (void)(t), NULL)
                #define XFREE(p, h, t)       do { (void)(p); (void)(h); (void)(t); } while(0)
                #define XREALLOC(p, n, h, t) ((void)(p), (void)(n), (void)(h), (void)(t), NULL)
            #endif
        #else
            /* just use plain C stdlib stuff if desired */
            #include <stdlib.h>
            #define XMALLOC(s, h, t)     ((void)(h), (void)(t), malloc((size_t)(s))) /* native heap */
            #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
                #define XFREE(p, h, t)       do { (void)(h); (void)(t); free(p); } while (0) /* native heap */
            #else
                #define XFREE(p, h, t)       do { void* xp = (p); (void)(h); if (xp) free(xp); } while (0) /* native heap */
            #endif
            #define XREALLOC(p, n, h, t) \
                ((void)(h), (void)(t), realloc((p), (size_t)(n))) /* native heap */
        #endif

    #elif defined(WOLFSSL_LINUXKM)

        /* definitions are in linuxkm/linuxkm_wc_port.h */

    #elif !defined(MICRIUM_MALLOC) && !defined(EBSNET) \
            && !defined(WOLFSSL_SAFERTOS) && !defined(FREESCALE_MQX) \
            && !defined(FREESCALE_KSDK_MQX) && !defined(FREESCALE_FREE_RTOS) \
            && !defined(WOLFSSL_LEANPSK) && !defined(WOLFSSL_uITRON4)
        /* default C runtime, can install different routines at runtime via cbs */
        #ifndef WOLFSSL_MEMORY_H
            #include <wolfssl/wolfcrypt/memory.h>
        #endif
        #ifdef WOLFSSL_STATIC_MEMORY
            #ifdef WOLFSSL_DEBUG_MEMORY
                #define XMALLOC(s, h, t)     wolfSSL_Malloc((s), (h), (t), __func__, __LINE__)
                #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
                    #define XFREE(p, h, t)       wolfSSL_Free(xp, h, t, __func__, __LINE__)
                #else
                    #define XFREE(p, h, t)       do { void* xp = (p); if (xp) wolfSSL_Free(xp, h, t, __func__, __LINE__); } while (0)
                #endif
                #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n), (h), (t), __func__, __LINE__)
            #else
                #define XMALLOC(s, h, t)     wolfSSL_Malloc((s), (h), (t))
                #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
                    #define XFREE(p, h, t)       wolfSSL_Free(xp, h, t)
                #else
                    #define XFREE(p, h, t)       do { void* xp = (p); if (xp) wolfSSL_Free(xp, h, t); } while (0)
                #endif
                #define XREALLOC(p, n, h, t) wolfSSL_Realloc((p), (n), (h), (t))
            #endif /* WOLFSSL_DEBUG_MEMORY */
        #elif  defined(WOLFSSL_EMBOS) && !defined(XMALLOC_USER) \
                && !defined(NO_WOLFSSL_MEMORY) \
                && !defined(WOLFSSL_STATIC_MEMORY)
            /* settings.h solve this case already. Avoid redefinition. */
        #elif (!defined(FREERTOS) && !defined(FREERTOS_TCP)) || defined(WOLFSSL_TRACK_MEMORY)
            #ifdef WOLFSSL_DEBUG_MEMORY
                #define XMALLOC(s, h, t)     ((void)(h), (void)(t), wolfSSL_Malloc((s), __func__, __LINE__))
                #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
                    #define XFREE(p, h, t)       do { (void)(h); (void)(t); wolfSSL_Free(xp, __func__, __LINE__); } while (0)
                #else
                    #define XFREE(p, h, t)       do { void* xp = (p); (void)(h); (void)(t); if (xp) wolfSSL_Free(xp, __func__, __LINE__); } while (0)
                #endif
                #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), wolfSSL_Realloc((p), (n), __func__, __LINE__))
            #else
                #define XMALLOC(s, h, t)     ((void)(h), (void)(t), wolfSSL_Malloc((s)))
                #ifdef WOLFSSL_XFREE_NO_NULLNESS_CHECK
                    #define XFREE(p, h, t)       do { (void)(h); (void)(t); wolfSSL_Free(p); } while (0)
                #else
                    #define XFREE(p, h, t)       do { void* xp = (p); (void)(h); (void)(t); if (xp) wolfSSL_Free(xp); } while (0)
                #endif
                #define XREALLOC(p, n, h, t) ((void)(h), (void)(t), wolfSSL_Realloc((p), (n)))
            #endif /* WOLFSSL_DEBUG_MEMORY */
        #endif /* WOLFSSL_STATIC_MEMORY */
    #endif

    #if defined(WOLFSSL_SMALL_STACK) && defined(WC_NO_CONSTRUCTORS)
        #error WOLFSSL_SMALL_STACK requires constructors.
    #endif

    #include <wolfssl/wolfcrypt/memory.h>

    /* declare/free variable handling for async and smallstack */
    #ifndef WC_ALLOC_DO_ON_FAILURE
        #define WC_ALLOC_DO_ON_FAILURE() WC_DO_NOTHING
    #endif

    #define WC_DECLARE_HEAP_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
        VAR_TYPE* VAR_NAME[VAR_ITEMS] = { NULL, }; \
        int idx##VAR_NAME = 0, inner_idx_##VAR_NAME
    #define WC_HEAP_ARRAY_ARG(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE) \
        VAR_TYPE* VAR_NAME[VAR_ITEMS]
    #define WC_ALLOC_HEAP_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
        for (idx##VAR_NAME=0; idx##VAR_NAME<(VAR_ITEMS); idx##VAR_NAME++) { \
            (VAR_NAME)[idx##VAR_NAME] = (VAR_TYPE*)XMALLOC(VAR_SIZE, (HEAP), DYNAMIC_TYPE_TMP_BUFFER); \
            if ((VAR_NAME)[idx##VAR_NAME] == NULL) { \
                for (inner_idx_##VAR_NAME = 0; inner_idx_##VAR_NAME < idx##VAR_NAME; inner_idx_##VAR_NAME++) { \
                    XFREE((VAR_NAME)[inner_idx_##VAR_NAME], (HEAP), DYNAMIC_TYPE_TMP_BUFFER); \
                    (VAR_NAME)[inner_idx_##VAR_NAME] = NULL; \
                } \
                for (inner_idx_##VAR_NAME = idx##VAR_NAME + 1; inner_idx_##VAR_NAME < (VAR_ITEMS); inner_idx_##VAR_NAME++) { \
                    (VAR_NAME)[inner_idx_##VAR_NAME] = NULL; \
                } \
                idx##VAR_NAME = 0; \
                WC_ALLOC_DO_ON_FAILURE(); \
                break; \
            } \
        }
    #define WC_CALLOC_HEAP_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
            do { \
                WC_ALLOC_HEAP_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP); \
                if (idx##VAR_NAME != 0) { \
                    for (idx##VAR_NAME=0; idx##VAR_NAME<(VAR_ITEMS); idx##VAR_NAME++) { \
                        XMEMSET((VAR_NAME)[idx##VAR_NAME], 0, VAR_SIZE); \
                    } \
                } \
            } while (0)
    #define WC_HEAP_ARRAY_OK(VAR_NAME) (idx##VAR_NAME != 0)
    #define WC_FREE_HEAP_ARRAY(VAR_NAME, VAR_ITEMS, HEAP)               \
        if (WC_HEAP_ARRAY_OK(VAR_NAME)) {                               \
            for (idx##VAR_NAME=0; idx##VAR_NAME<(VAR_ITEMS); idx##VAR_NAME++) { \
                XFREE((VAR_NAME)[idx##VAR_NAME], (HEAP), DYNAMIC_TYPE_TMP_BUFFER); \
            }                                                           \
            idx##VAR_NAME = 0;                                          \
        }

    #if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_SMALL_STACK)
        #define WC_DECLARE_VAR_IS_HEAP_ALLOC
        #define WC_DECLARE_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP) \
            VAR_TYPE* VAR_NAME = NULL
        #define WC_ALLOC_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP)        \
            do {                                                        \
                (VAR_NAME) = (VAR_TYPE*)XMALLOC(sizeof(VAR_TYPE) * (VAR_SIZE), (HEAP), DYNAMIC_TYPE_WOLF_BIGINT); \
                if ((VAR_NAME) == NULL) {                               \
                    WC_ALLOC_DO_ON_FAILURE();                           \
                }                                                       \
            } while (0)
        #define WC_CALLOC_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP)        \
            do { \
                WC_ALLOC_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP); \
                XMEMSET(VAR_NAME, 0, sizeof(VAR_TYPE) * (VAR_SIZE)); \
            } while (0)
        #define WC_FREE_VAR(VAR_NAME, HEAP) \
            XFREE(VAR_NAME, (HEAP), DYNAMIC_TYPE_WOLF_BIGINT)
        #define WC_DECLARE_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
            WC_DECLARE_HEAP_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP)
        #define WC_ARRAY_ARG(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE) \
            WC_HEAP_ARRAY_ARG(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE)
        #define WC_ALLOC_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
            WC_ALLOC_HEAP_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP)
        #define WC_CALLOC_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
            WC_CALLOC_HEAP_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP)
        #define WC_ARRAY_OK(VAR_NAME) WC_HEAP_ARRAY_OK(VAR_NAME)
        #define WC_FREE_ARRAY(VAR_NAME, VAR_ITEMS, HEAP) \
            WC_FREE_HEAP_ARRAY(VAR_NAME, VAR_ITEMS, HEAP)
    #else
        #undef WC_DECLARE_VAR_IS_HEAP_ALLOC
        #define WC_DECLARE_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP) \
            VAR_TYPE VAR_NAME[VAR_SIZE]
        #define WC_ALLOC_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP) WC_DO_NOTHING
        #define WC_CALLOC_VAR(VAR_NAME, VAR_TYPE, VAR_SIZE, HEAP)        \
            XMEMSET(VAR_NAME, 0, sizeof(var))
        #define WC_FREE_VAR(VAR_NAME, HEAP) WC_DO_NOTHING /* nothing to free, its stack */
        #define WC_DECLARE_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) \
            VAR_TYPE VAR_NAME[VAR_ITEMS][(VAR_SIZE) / sizeof(VAR_TYPE)] /* // NOLINT(bugprone-sizeof-expression) */
        #define WC_ARRAY_ARG(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE) \
            VAR_TYPE VAR_NAME[VAR_ITEMS][(VAR_SIZE) / sizeof(VAR_TYPE)] /* // NOLINT(bugprone-sizeof-expression) */
        #define WC_ALLOC_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) WC_DO_NOTHING
        #define WC_CALLOC_ARRAY(VAR_NAME, VAR_TYPE, VAR_ITEMS, VAR_SIZE, HEAP) XMEMSET(VAR_NAME, 0, sizeof(VAR_NAME))
        #define WC_ARRAY_OK(VAR_NAME) 1
        #define WC_FREE_ARRAY(VAR_NAME, VAR_ITEMS, HEAP) WC_DO_NOTHING /* nothing to free, its stack */
    #endif

    #if defined(HAVE_FIPS) || defined(HAVE_SELFTEST)
        /* These are here for the FIPS code that can't be changed. New definitions don't need to be added here. */
        #define DECLARE_VAR                 WC_DECLARE_VAR
        #define DECLARE_ARRAY               WC_DECLARE_ARRAY
        #define FREE_VAR                    WC_FREE_VAR
        #define FREE_ARRAY                  WC_FREE_ARRAY
        #define DECLARE_ARRAY_DYNAMIC_DEC   WC_DECLARE_HEAP_ARRAY
        #define DECLARE_ARRAY_DYNAMIC_EXE   WC_ALLOC_HEAP_ARRAY
        #define FREE_ARRAY_DYNAMIC          WC_FREE_HEAP_ARRAY
    #endif /* HAVE_FIPS */

    #if !defined(USE_WOLF_STRTOK) && \
            ((defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)) || \
             defined(WOLFSSL_TIRTOS) || defined(WOLF_C99))
        #define USE_WOLF_STRTOK
    #endif
    #if !defined(USE_WOLF_STRSEP) && (defined(WOLF_C89) || defined(WOLF_C99))
        #define USE_WOLF_STRSEP
    #endif
    #if !defined(XSTRLCPY) && !defined(USE_WOLF_STRLCPY)
        #define USE_WOLF_STRLCPY
    #endif
    #if !defined(XSTRLCAT) && !defined(USE_WOLF_STRLCAT)
        #define USE_WOLF_STRLCAT
    #endif

        #ifndef STRING_USER
        #if defined(WOLFSSL_LINUXKM)
            #include <linux/string.h>
        #else
            #include <string.h>
        #endif

        #define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
        #define XMEMSET(b,c,l)    memset((b),(c),(l))
        #define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
        #define XMEMMOVE(d,s,l)   memmove((d),(s),(l))

        #define XSTRLEN(s1)       strlen((s1))
        #define XSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
        /* strstr, strncmp, strcmp, and strncat only used by wolfSSL proper,
         * not required for wolfCrypt only */
        #define XSTRSTR(s1,s2)    strstr((s1),(s2))
        #define XSTRNSTR(s1,s2,n) mystrnstr((s1),(s2),(n))
        #define XSTRNCMP(s1,s2,n) strncmp((s1),(s2),(n))
        #define XSTRCMP(s1,s2)    strcmp((s1),(s2))
        #define XSTRNCAT(s1,s2,n) strncat((s1),(s2),(n))

        #ifdef USE_WOLF_STRSEP
            #define XSTRSEP(s1,d) wc_strsep((s1),(d))
        #else
            #define XSTRSEP(s1,d) strsep((s1),(d))
        #endif

        #ifndef XSTRCASECMP
        #if defined(MICROCHIP_PIC32) && (__XC32_VERSION >= 1000) && (__XC32_VERSION < 4000)
            /* XC32 supports str[n]casecmp in version >= 1.0 through 4.0. */
            #define XSTRCASECMP(s1,s2) strcasecmp((s1),(s2))
        #elif defined(MICROCHIP_PIC32) || defined(WOLFSSL_TIRTOS) || \
                defined(WOLFSSL_ZEPHYR) || defined(MICROCHIP_PIC24)
            /* XC32 version < 1.0 does not support strcasecmp. */
            #define USE_WOLF_STRCASECMP
        #elif defined(USE_WINDOWS_API) || defined(FREERTOS_TCP_WINSIM)
            #define XSTRCASECMP(s1,s2) _stricmp((s1),(s2))
        #else
            #if defined(HAVE_STRINGS_H) && defined(WOLF_C99) && \
                !defined(WOLFSSL_SGX)
                #include <strings.h>
            #endif
            #if defined(WOLFSSL_DEOS)
                #define XSTRCASECMP(s1,s2) stricmp((s1),(s2))
            #elif defined(WOLFSSL_CMSIS_RTOSv2) || defined(WOLFSSL_AZSPHERE) \
                    || defined(WOLF_C89)
                #define USE_WOLF_STRCASECMP
            #elif defined(WOLF_C89)
                #define XSTRCASECMP(s1,s2) strcmp((s1),(s2))
            #else
                #define XSTRCASECMP(s1,s2) strcasecmp((s1),(s2))
            #endif
        #endif
        #ifdef USE_WOLF_STRCASECMP
            #undef  XSTRCASECMP
            #define XSTRCASECMP(s1,s2) wc_strcasecmp((s1), (s2))
        #endif
        #endif /* !XSTRCASECMP */

        #ifndef XSTRNCASECMP
        #if defined(MICROCHIP_PIC32) && (__XC32_VERSION >= 1000)
            /* XC32 supports str[n]casecmp in version >= 1.0. */
            #define XSTRNCASECMP(s1,s2,n) strncasecmp((s1),(s2),(n))
        #elif defined(MICROCHIP_PIC32) || defined(WOLFSSL_TIRTOS) || \
                defined(WOLFSSL_ZEPHYR) || defined(MICROCHIP_PIC24)
            /* XC32 version < 1.0 does not support strncasecmp. */
            #define USE_WOLF_STRNCASECMP
        #elif defined(USE_WINDOWS_API) || defined(FREERTOS_TCP_WINSIM)
            #define XSTRNCASECMP(s1,s2,n) _strnicmp((s1),(s2),(n))
        #else
            #if defined(HAVE_STRINGS_H) && defined(WOLF_C99) && \
                !defined(WOLFSSL_SGX)
                #include <strings.h>
            #endif
            #if defined(WOLFSSL_DEOS)
                #define XSTRNCASECMP(s1,s2,n) strnicmp((s1),(s2),(n))
            #elif defined(WOLFSSL_CMSIS_RTOSv2) || defined(WOLFSSL_AZSPHERE) \
                    || defined(WOLF_C89)
                #define USE_WOLF_STRNCASECMP
            #elif defined(WOLF_C89)
                #define XSTRNCASECMP(s1,s2,n) strncmp((s1),(s2),(n))
            #else
                #define XSTRNCASECMP(s1,s2,n) strncasecmp((s1),(s2),(n))
            #endif
        #endif
        #ifdef USE_WOLF_STRNCASECMP
            #undef  XSTRNCASECMP
            #define XSTRNCASECMP(s1,s2,n) wc_strncasecmp((s1),(s2),(n))
        #endif
        #endif /* !XSTRNCASECMP */

        /* snprintf is used in asn.c for GetTimeString, PKCS7 test, and when
           debugging is turned on */
        #ifndef XSNPRINTF
        #ifndef USE_WINDOWS_API
            #if defined(WOLFSSL_ESPIDF) && \
                (!defined(NO_ASN_TIME) && defined(HAVE_PKCS7))
                    #include <stdarg.h>
                    /* later gcc than 7.1 introduces -Wformat-truncation    */
                    /* In cases when truncation is expected the caller needs*/
                    /* to check the return value from the function so that  */
                    /* compiler doesn't complain.                           */
                    /* xtensa-esp32-elf v8.2.0 warns truncation at          */
                    /* GetAsnTimeString()                                   */
                    static WC_INLINE
                    int _xsnprintf_(char *s, size_t n, const char *format, ...)
                    {
                        va_list ap;
                        int ret;

                        if ((int)n <= 0) return -1;

                        va_start(ap, format);

                        ret = XVSNPRINTF(s, n, format, ap);
                        if (ret < 0)
                            ret = -1;

                        va_end(ap);

                        return ret;
                    }
                #define XSNPRINTF _xsnprintf_
            #elif defined(FREESCALE_MQX)
                /* see wc_port.h for fio.h and nio.h includes.  MQX does not
                   have stdio.h available, so it needs its own section. */
                #define XSNPRINTF snprintf
            #elif defined(WOLF_C89)
                #ifndef NO_STDIO_FILESYSTEM
                #include <stdio.h>
                #endif
                #define XSPRINTF sprintf
                /* snprintf not available for C89, so remap using macro */
                #ifdef WOLF_NO_VARIADIC_MACROS
                    #error WOLF_NO_VARIADIC_MACROS requires user-supplied binding for XSNPRINTF
                #else
                    #define XSNPRINTF(f, len, ...) sprintf(f, __VA_ARGS__)
                #endif
            #else
                #ifndef NO_STDIO_FILESYSTEM
                #include <stdio.h>
                #endif
                #define XSNPRINTF snprintf
            #endif
        #else
            #if defined(_MSC_VER) || defined(__CYGWIN__) || defined(__MINGW32__)
                #if defined(_MSC_VER) && (_MSC_VER >= 1900)
                    /* Beginning with the UCRT in Visual Studio 2015 and
                     * Windows 10, snprintf is no longer identical to
                     * _snprintf. The snprintf function behavior is now
                     * C99 standard compliant. */
                    #include <stdio.h>
                    #define XSNPRINTF snprintf
                #else
                    /* 4996 warning to use MS extensions e.g., _sprintf_s
                     * instead of _snprintf */
                    #if !defined(__MINGW32__)
                    #pragma warning(disable: 4996)
                    #endif
                    #include <stdarg.h>
                    static WC_INLINE
                    int xsnprintf(char *buffer, size_t bufsize,
                            const char *format, ...) {
                        va_list ap;
                        int ret;

                        if ((int)bufsize <= 0) return -1;
                        va_start(ap, format);
                        ret = XVSNPRINTF(buffer, bufsize, format, ap);
                        if (ret >= (int)bufsize)
                            ret = -1;
                        va_end(ap);
                        return ret;
                    }
                    #define XSNPRINTF xsnprintf
                #endif /* (_MSC_VER >= 1900) */
            #else
                #define XSNPRINTF snprintf
            #endif /* _MSC_VER */
        #endif /* USE_WINDOWS_API */
        #endif /* !XSNPRINTF */

        #if defined(WOLFSSL_CERT_EXT) || defined(OPENSSL_EXTRA) || \
            defined(HAVE_ALPN) || defined(WOLFSSL_SNIFFER) || \
            defined(WOLFSSL_ASN_PARSE_KEYUSAGE)
            /* use only Thread Safe version of strtok */
            #if defined(USE_WOLF_STRTOK)
                #define XSTRTOK(s1,d,ptr) wc_strtok((s1),(d),(ptr))
            #elif defined(USE_WINDOWS_API) || defined(INTIME_RTOS)
                #define XSTRTOK(s1,d,ptr) strtok_s((s1),(d),(ptr))
            #else
                #define XSTRTOK(s1,d,ptr) strtok_r((s1),(d),(ptr))
            #endif
        #endif

        #if defined(WOLFSSL_CERT_EXT) || defined(HAVE_OCSP) || \
            defined(HAVE_CRL_IO) || defined(HAVE_HTTP_CLIENT) || \
            !defined(NO_CRYPT_BENCHMARK) || defined(OPENSSL_EXTRA)

            #ifndef XATOI /* if custom XATOI is not already defined */
                #include <stdlib.h>
                #define XATOI(s)          atoi((s))
            #endif
        #endif
    #endif

    #ifdef USE_WOLF_STRTOK
        WOLFSSL_API char* wc_strtok(char *str, const char *delim, char **nextp);
    #endif
    #ifdef USE_WOLF_STRSEP
        WOLFSSL_API char* wc_strsep(char **stringp, const char *delim);
    #endif

    #ifdef USE_WOLF_STRLCPY
        WOLFSSL_API size_t wc_strlcpy(char *dst, const char *src, size_t dstSize);
        #define XSTRLCPY(s1,s2,n) wc_strlcpy((s1),(s2),(n))
    #endif
    #ifdef USE_WOLF_STRLCAT
        WOLFSSL_API size_t wc_strlcat(char *dst, const char *src, size_t dstSize);
        #define XSTRLCAT(s1,s2,n) wc_strlcat((s1),(s2),(n))
    #endif
    #ifdef USE_WOLF_STRCASECMP
        WOLFSSL_API int wc_strcasecmp(const char *s1, const char *s2);
    #endif
    #ifdef USE_WOLF_STRNCASECMP
        WOLFSSL_API int wc_strncasecmp(const char *s1, const char *s2, size_t n);
    #endif

    #if !defined(XSTRDUP) && !defined(USE_WOLF_STRDUP)
        #define USE_WOLF_STRDUP
    #endif
    #ifdef USE_WOLF_STRDUP
        WOLFSSL_LOCAL char* wc_strdup_ex(const char *src, int memType);
        #define wc_strdup(src) wc_strdup_ex(src, DYNAMIC_TYPE_TMP_BUFFER)
        #define XSTRDUP(src) wc_strdup(src)
    #endif

    #if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
        #ifndef XGETENV
            #ifdef NO_GETENV
                #define XGETENV(x) (NULL)
            #else
                #include <stdlib.h>
                #define XGETENV getenv
            #endif
        #endif
    #endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */

    #ifndef CTYPE_USER
        #ifndef WOLFSSL_LINUXKM
            #include <ctype.h>
        #endif
        #if defined(HAVE_ECC) || defined(HAVE_OCSP) || \
        defined(WOLFSSL_KEY_GEN) || !defined(NO_DSA) || \
        defined(OPENSSL_EXTRA)
            #define XTOUPPER(c)     toupper((c))
        #endif
        #if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        #define XISALNUM(c)     isalnum((c))
        #ifdef NO_STDLIB_ISASCII
            #define XISASCII(c) (((c) >= 0 && (c) <= 127) ? 1 : 0)
        #else
            #define XISASCII(c) isascii((c))
        #endif
        #define XISSPACE(c)     isspace((c))
        #endif
        /* needed by wolfSSL_check_domain_name() */
        #define XTOLOWER(c)      tolower((c))
    #endif

    #ifndef OFFSETOF
        #if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ >= 4))
            #define OFFSETOF(type, field) __builtin_offsetof(type, field)
        #else
            #define OFFSETOF(type, field) ((size_t)&(((type *)0)->field))
        #endif
    #endif


    /* memory allocation types for user hints */
    enum {
        DYNAMIC_TYPE_CA           = 1,
        DYNAMIC_TYPE_CERT         = 2,
        DYNAMIC_TYPE_KEY          = 3,
        DYNAMIC_TYPE_FILE         = 4,
        DYNAMIC_TYPE_SUBJECT_CN   = 5,
        DYNAMIC_TYPE_PUBLIC_KEY   = 6,
        DYNAMIC_TYPE_SIGNER       = 7,
        DYNAMIC_TYPE_NONE         = 8,
        DYNAMIC_TYPE_BIGINT       = 9,
        DYNAMIC_TYPE_RSA          = 10,
        DYNAMIC_TYPE_METHOD       = 11,
        DYNAMIC_TYPE_OUT_BUFFER   = 12,
        DYNAMIC_TYPE_IN_BUFFER    = 13,
        DYNAMIC_TYPE_INFO         = 14,
        DYNAMIC_TYPE_DH           = 15,
        DYNAMIC_TYPE_DOMAIN       = 16,
        DYNAMIC_TYPE_SSL          = 17,
        DYNAMIC_TYPE_CTX          = 18,
        DYNAMIC_TYPE_WRITEV       = 19,
        DYNAMIC_TYPE_OPENSSL      = 20,
        DYNAMIC_TYPE_DSA          = 21,
        DYNAMIC_TYPE_CRL          = 22,
        DYNAMIC_TYPE_REVOKED      = 23,
        DYNAMIC_TYPE_CRL_ENTRY    = 24,
        DYNAMIC_TYPE_CERT_MANAGER = 25,
        DYNAMIC_TYPE_CRL_MONITOR  = 26,
        DYNAMIC_TYPE_OCSP_STATUS  = 27,
        DYNAMIC_TYPE_OCSP_ENTRY   = 28,
        DYNAMIC_TYPE_ALTNAME      = 29,
        DYNAMIC_TYPE_SUITES       = 30,
        DYNAMIC_TYPE_CIPHER       = 31,
        DYNAMIC_TYPE_RNG          = 32,
        DYNAMIC_TYPE_ARRAYS       = 33,
        DYNAMIC_TYPE_DTLS_POOL    = 34,
        DYNAMIC_TYPE_SOCKADDR     = 35,
        DYNAMIC_TYPE_LIBZ         = 36,
        DYNAMIC_TYPE_ECC          = 37,
        DYNAMIC_TYPE_TMP_BUFFER   = 38,
        DYNAMIC_TYPE_DTLS_MSG     = 39,
        DYNAMIC_TYPE_X509         = 40,
        DYNAMIC_TYPE_TLSX         = 41,
        DYNAMIC_TYPE_OCSP         = 42,
        DYNAMIC_TYPE_SIGNATURE    = 43,
        DYNAMIC_TYPE_HASHES       = 44,
        DYNAMIC_TYPE_SRP          = 45,
        DYNAMIC_TYPE_COOKIE_PWD   = 46,
        DYNAMIC_TYPE_USER_CRYPTO  = 47,
        DYNAMIC_TYPE_OCSP_REQUEST = 48,
        DYNAMIC_TYPE_X509_EXT     = 49,
        DYNAMIC_TYPE_X509_STORE   = 50,
        DYNAMIC_TYPE_X509_CTX     = 51,
        DYNAMIC_TYPE_URL          = 52,
        DYNAMIC_TYPE_DTLS_FRAG    = 53,
        DYNAMIC_TYPE_DTLS_BUFFER  = 54,
        DYNAMIC_TYPE_SESSION_TICK = 55,
        DYNAMIC_TYPE_PKCS         = 56,
        DYNAMIC_TYPE_MUTEX        = 57,
        DYNAMIC_TYPE_PKCS7        = 58,
        DYNAMIC_TYPE_AES_BUFFER   = 59,
        DYNAMIC_TYPE_WOLF_BIGINT  = 60,
        DYNAMIC_TYPE_ASN1         = 61,
        DYNAMIC_TYPE_LOG          = 62,
        DYNAMIC_TYPE_WRITEDUP     = 63,
        DYNAMIC_TYPE_PRIVATE_KEY  = 64,
        DYNAMIC_TYPE_HMAC         = 65,
        DYNAMIC_TYPE_ASYNC        = 66,
        DYNAMIC_TYPE_ASYNC_NUMA   = 67,
        DYNAMIC_TYPE_ASYNC_NUMA64 = 68,
        DYNAMIC_TYPE_CURVE25519   = 69,
        DYNAMIC_TYPE_ED25519      = 70,
        DYNAMIC_TYPE_SECRET       = 71,
        DYNAMIC_TYPE_DIGEST       = 72,
        DYNAMIC_TYPE_RSA_BUFFER   = 73,
        DYNAMIC_TYPE_DCERT        = 74,
        DYNAMIC_TYPE_STRING       = 75,
        DYNAMIC_TYPE_PEM          = 76,
        DYNAMIC_TYPE_DER          = 77,
        DYNAMIC_TYPE_CERT_EXT     = 78,
        DYNAMIC_TYPE_ALPN         = 79,
        DYNAMIC_TYPE_ENCRYPTEDINFO= 80,
        DYNAMIC_TYPE_DIRCTX       = 81,
        DYNAMIC_TYPE_HASHCTX      = 82,
        DYNAMIC_TYPE_SEED         = 83,
        DYNAMIC_TYPE_SYMMETRIC_KEY= 84,
        DYNAMIC_TYPE_ECC_BUFFER   = 85,
        DYNAMIC_TYPE_SALT         = 87,
        DYNAMIC_TYPE_HASH_TMP     = 88,
        DYNAMIC_TYPE_BLOB         = 89,
        DYNAMIC_TYPE_NAME_ENTRY   = 90,
        DYNAMIC_TYPE_CURVE448     = 91,
        DYNAMIC_TYPE_ED448        = 92,
        DYNAMIC_TYPE_AES          = 93,
        DYNAMIC_TYPE_CMAC         = 94,
        DYNAMIC_TYPE_FALCON       = 95,
        DYNAMIC_TYPE_SESSION      = 96,
        DYNAMIC_TYPE_DILITHIUM    = 97,
        DYNAMIC_TYPE_SPHINCS      = 98,
        DYNAMIC_TYPE_SM4_BUFFER   = 99,
        DYNAMIC_TYPE_DEBUG_TAG    = 100,
        DYNAMIC_TYPE_LMS          = 101,
        DYNAMIC_TYPE_BIO          = 102,
        DYNAMIC_TYPE_X509_ACERT   = 103,
        DYNAMIC_TYPE_OS_BUF       = 104,
        DYNAMIC_TYPE_SNIFFER_SERVER       = 1000,
        DYNAMIC_TYPE_SNIFFER_SESSION      = 1001,
        DYNAMIC_TYPE_SNIFFER_PB           = 1002,
        DYNAMIC_TYPE_SNIFFER_PB_BUFFER    = 1003,
        DYNAMIC_TYPE_SNIFFER_TICKET_ID    = 1004,
        DYNAMIC_TYPE_SNIFFER_NAMED_KEY    = 1005,
        DYNAMIC_TYPE_SNIFFER_KEY          = 1006,
        DYNAMIC_TYPE_SNIFFER_KEYLOG_NODE  = 1007,
        DYNAMIC_TYPE_SNIFFER_CHAIN_BUFFER = 1008,
        DYNAMIC_TYPE_AES_EAX = 1009
    };

    /* max error buffer string size */
    #ifndef WOLFSSL_MAX_ERROR_SZ
        #define WOLFSSL_MAX_ERROR_SZ 80
    #endif

    /* stack protection */
    enum {
        MIN_STACK_BUFFER = 8
    };


    /* Algorithm Types */
    enum wc_AlgoType {
        WC_ALGO_TYPE_NONE = 0,
        WC_ALGO_TYPE_HASH = 1,
        WC_ALGO_TYPE_CIPHER = 2,
        WC_ALGO_TYPE_PK = 3,
        WC_ALGO_TYPE_RNG = 4,
        WC_ALGO_TYPE_SEED = 5,
        WC_ALGO_TYPE_HMAC = 6,
        WC_ALGO_TYPE_CMAC = 7,
        WC_ALGO_TYPE_CERT = 8,

        WC_ALGO_TYPE_MAX = WC_ALGO_TYPE_CERT
    };

    /* hash types */
    enum wc_HashType {
    #if defined(HAVE_SELFTEST) || (defined(HAVE_FIPS) && \
        ((! defined(HAVE_FIPS_VERSION)) || \
         defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION <= 2)))
        /* In selftest build, WC_* types are not mapped to WC_HASH_TYPE types.
         * Values here are based on old selftest hmac.h enum, with additions.
         * These values are fixed for backwards FIPS compatibility */
        WC_HASH_TYPE_NONE = 15,
        WC_HASH_TYPE_MD2 = 16,
        WC_HASH_TYPE_MD4 = 17,
        WC_HASH_TYPE_MD5 = 0,
        WC_HASH_TYPE_SHA = 1, /* SHA-1 (not old SHA-0) */
        WC_HASH_TYPE_SHA224 = 8,
        WC_HASH_TYPE_SHA256 = 2,
        WC_HASH_TYPE_SHA384 = 5,
        WC_HASH_TYPE_SHA512 = 4,
        WC_HASH_TYPE_MD5_SHA = 18,
        WC_HASH_TYPE_SHA3_224 = 10,
        WC_HASH_TYPE_SHA3_256 = 11,
        WC_HASH_TYPE_SHA3_384 = 12,
        WC_HASH_TYPE_SHA3_512 = 13,
        WC_HASH_TYPE_BLAKE2B = 14,
        WC_HASH_TYPE_BLAKE2S = 19,
        WC_HASH_TYPE_MAX = WC_HASH_TYPE_BLAKE2S,
        #ifndef WOLFSSL_NOSHA512_224
            #define WOLFSSL_NOSHA512_224
        #endif
        #ifndef WOLFSSL_NOSHA512_256
            #define WOLFSSL_NOSHA512_256
        #endif
    #else
        WC_HASH_TYPE_NONE = 0,
        WC_HASH_TYPE_MD2 = 1,
        WC_HASH_TYPE_MD4 = 2,
        WC_HASH_TYPE_MD5 = 3,
        WC_HASH_TYPE_SHA = 4, /* SHA-1 (not old SHA-0) */
        WC_HASH_TYPE_SHA224 = 5,
        WC_HASH_TYPE_SHA256 = 6,
        WC_HASH_TYPE_SHA384 = 7,
        WC_HASH_TYPE_SHA512 = 8,
        WC_HASH_TYPE_MD5_SHA = 9,
        WC_HASH_TYPE_SHA3_224 = 10,
        WC_HASH_TYPE_SHA3_256 = 11,
        WC_HASH_TYPE_SHA3_384 = 12,
        WC_HASH_TYPE_SHA3_512 = 13,
        WC_HASH_TYPE_BLAKE2B = 14,
        WC_HASH_TYPE_BLAKE2S = 15,
        #define _WC_HASH_TYPE_MAX WC_HASH_TYPE_BLAKE2S
        #ifndef WOLFSSL_NOSHA512_224
            WC_HASH_TYPE_SHA512_224 = 16,
            #undef _WC_HASH_TYPE_MAX
            #define _WC_HASH_TYPE_MAX WC_HASH_TYPE_SHA512_224
        #endif
        #ifndef WOLFSSL_NOSHA512_256
            WC_HASH_TYPE_SHA512_256 = 17,
            #undef _WC_HASH_TYPE_MAX
            #define _WC_HASH_TYPE_MAX WC_HASH_TYPE_SHA512_256
        #endif
        #ifdef WOLFSSL_SHAKE128
            WC_HASH_TYPE_SHAKE128 = 18,
            #undef _WC_HASH_TYPE_MAX
            #define _WC_HASH_TYPE_MAX WC_HASH_TYPE_SHAKE128
        #endif
        #ifdef WOLFSSL_SHAKE256
            WC_HASH_TYPE_SHAKE256 = 19,
            #undef _WC_HASH_TYPE_MAX
            #define _WC_HASH_TYPE_MAX WC_HASH_TYPE_SHAKE256
        #endif
        #ifdef WOLFSSL_SM3
            WC_HASH_TYPE_SM3     = 20,
            #undef _WC_HASH_TYPE_MAX
            #define _WC_HASH_TYPE_MAX WC_HASH_TYPE_SM3
        #endif
        WC_HASH_TYPE_MAX = _WC_HASH_TYPE_MAX
        #undef _WC_HASH_TYPE_MAX

    #endif /* HAVE_SELFTEST */
    };

    /* cipher types */
    enum wc_CipherType {
        WC_CIPHER_NONE = 0,
        WC_CIPHER_AES = 1,
        WC_CIPHER_AES_CBC = 2,
        WC_CIPHER_AES_GCM = 3,
        WC_CIPHER_AES_CTR = 4,
        WC_CIPHER_AES_XTS = 5,
        WC_CIPHER_AES_CFB = 6,
        WC_CIPHER_AES_CCM = 12,
        WC_CIPHER_AES_ECB = 13,
        WC_CIPHER_DES3 = 7,
        WC_CIPHER_DES = 8,
        WC_CIPHER_CHACHA = 9,

        WC_CIPHER_MAX = WC_CIPHER_AES_CCM
    };

    /* PK=public key (asymmetric) based algorithms */
    enum wc_PkType {
        WC_PK_TYPE_NONE = 0,
        WC_PK_TYPE_RSA = 1,
        WC_PK_TYPE_DH = 2,
        WC_PK_TYPE_ECDH = 3,
        WC_PK_TYPE_ECDSA_SIGN = 4,
        WC_PK_TYPE_ECDSA_VERIFY = 5,
        WC_PK_TYPE_ED25519_SIGN = 6,
        WC_PK_TYPE_CURVE25519 = 7,
        WC_PK_TYPE_RSA_KEYGEN = 8,
        WC_PK_TYPE_EC_KEYGEN = 9,
        WC_PK_TYPE_RSA_CHECK_PRIV_KEY = 10,
        WC_PK_TYPE_EC_CHECK_PRIV_KEY = 11,
        WC_PK_TYPE_ED448 = 12,
        WC_PK_TYPE_CURVE448 = 13,
        WC_PK_TYPE_ED25519_VERIFY = 14,
        WC_PK_TYPE_ED25519_KEYGEN = 15,
        WC_PK_TYPE_CURVE25519_KEYGEN = 16,
        WC_PK_TYPE_RSA_GET_SIZE = 17,
        #define _WC_PK_TYPE_MAX WC_PK_TYPE_RSA_GET_SIZE
    #if defined(WOLFSSL_HAVE_KYBER)
        WC_PK_TYPE_PQC_KEM_KEYGEN = 18,
        WC_PK_TYPE_PQC_KEM_ENCAPS = 19,
        WC_PK_TYPE_PQC_KEM_DECAPS = 20,
        #undef _WC_PK_TYPE_MAX
        #define _WC_PK_TYPE_MAX WC_PK_TYPE_PQC_KEM_DECAPS
    #endif
    #if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
        WC_PK_TYPE_PQC_SIG_KEYGEN = 21,
        WC_PK_TYPE_PQC_SIG_SIGN = 22,
        WC_PK_TYPE_PQC_SIG_VERIFY = 23,
        WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY = 24,
        #undef _WC_PK_TYPE_MAX
        #define _WC_PK_TYPE_MAX WC_PK_TYPE_PQC_SIG_CHECK_PRIV_KEY
    #endif
        WC_PK_TYPE_RSA_PKCS = 25,
        WC_PK_TYPE_RSA_PSS = 26,
        WC_PK_TYPE_RSA_OAEP = 27,
        WC_PK_TYPE_MAX = _WC_PK_TYPE_MAX
    };

#if defined(WOLFSSL_HAVE_KYBER)
    /* Post quantum KEM algorithms */
    enum wc_PqcKemType {
        WC_PQC_KEM_TYPE_NONE = 0,
        #define _WC_PQC_KEM_TYPE_MAX WC_PQC_KEM_TYPE_NONE
    #if defined(WOLFSSL_HAVE_KYBER)
        WC_PQC_KEM_TYPE_KYBER = 1,
        #undef _WC_PQC_KEM_TYPE_MAX
        #define _WC_PQC_KEM_TYPE_MAX WC_PQC_KEM_TYPE_KYBER
    #endif
        WC_PQC_KEM_TYPE_MAX = _WC_PQC_KEM_TYPE_MAX
    };
#endif

#if defined(HAVE_DILITHIUM) || defined(HAVE_FALCON)
    /* Post quantum signature algorithms */
    enum wc_PqcSignatureType {
        WC_PQC_SIG_TYPE_NONE = 0,
        #define _WC_PQC_SIG_TYPE_MAX WC_PQC_SIG_TYPE_NONE
    #if defined(HAVE_DILITHIUM)
        WC_PQC_SIG_TYPE_DILITHIUM = 1,
        #undef _WC_PQC_SIG_TYPE_MAX
        #define _WC_PQC_SIG_TYPE_MAX WC_PQC_SIG_TYPE_DILITHIUM
    #endif
    #if defined(HAVE_FALCON)
        WC_PQC_SIG_TYPE_FALCON = 2,
        #undef _WC_PQC_SIG_TYPE_MAX
        #define _WC_PQC_SIG_TYPE_MAX WC_PQC_SIG_TYPE_FALCON
    #endif
        WC_PQC_SIG_TYPE_MAX = _WC_PQC_SIG_TYPE_MAX
    };
#endif

    /* settings detection for compile vs runtime math incompatibilities */
    enum {
    #if !defined(USE_FAST_MATH) && !defined(SIZEOF_LONG) && !defined(SIZEOF_LONG_LONG)
        CTC_SETTINGS = 0x0
    #elif !defined(USE_FAST_MATH) && defined(SIZEOF_LONG) && (SIZEOF_LONG == 8)
        CTC_SETTINGS = 0x1
    #elif !defined(USE_FAST_MATH) && defined(SIZEOF_LONG_LONG) && (SIZEOF_LONG_LONG == 8)
        CTC_SETTINGS = 0x2
    #elif !defined(USE_FAST_MATH) && defined(SIZEOF_LONG_LONG) && (SIZEOF_LONG_LONG == 4)
        CTC_SETTINGS = 0x4
    #elif defined(USE_FAST_MATH) && !defined(SIZEOF_LONG) && !defined(SIZEOF_LONG_LONG)
        CTC_SETTINGS = 0x8
    #elif defined(USE_FAST_MATH) && defined(SIZEOF_LONG) && (SIZEOF_LONG == 8)
        CTC_SETTINGS = 0x10
    #elif defined(USE_FAST_MATH) && defined(SIZEOF_LONG_LONG) && (SIZEOF_LONG_LONG == 8)
        CTC_SETTINGS = 0x20
    #elif defined(USE_FAST_MATH) && defined(SIZEOF_LONG_LONG) && (SIZEOF_LONG_LONG == 4)
        CTC_SETTINGS = 0x40
    #else
        #error "bad math long / long long settings"
    #endif
    };


    WOLFSSL_API word32 CheckRunTimeSettings(void);

    /* If user uses RSA, DH, DSA, or ECC math lib directly then fast math and long
       types need to match at compile time and run time, CheckCtcSettings will
       return 1 if a match otherwise 0 */
    #define CheckCtcSettings() (CTC_SETTINGS == CheckRunTimeSettings())

    /* invalid device id */
    #define INVALID_DEVID    (-2)

    #if defined(HAVE_FIPS) && FIPS_VERSION_LT(5,3)
        #ifdef XASM_LINK
            #error User-supplied XASM_LINK is not compatible with this FIPS version.
        #else
            /* use version in FIPS <=5.2 aes.c */
        #endif
    #elif defined(XASM_LINK)
        /* keep user-supplied definition */
    #elif defined(WOLFSSL_NO_ASM)
        #define XASM_LINK(f) /* null expansion */
    #elif defined(_MSC_VER)
        #define XASM_LINK(f) /* null expansion */
    #elif defined(__APPLE__)
        #define XASM_LINK(f) asm("_" f)
    #elif defined(__GNUC__)
        /* use alternate keyword for compatibility with -std=c99 */
        #define XASM_LINK(f) __asm__(f)
    #else
        #define XASM_LINK(f) asm(f)
    #endif

    /* AESNI requires alignment and ARMASM gains some performance from it.
     * Xilinx RSA operations require alignment.
     */
    #if defined(WOLFSSL_AESNI) || defined(WOLFSSL_ARMASM) || \
        defined(USE_INTEL_SPEEDUP) || defined(WOLFSSL_AFALG_XILINX) || \
        defined(WOLFSSL_XILINX)
          #ifndef WOLFSSL_USE_ALIGN
              #define WOLFSSL_USE_ALIGN
          #endif
    #endif /* WOLFSSL_AESNI || WOLFSSL_ARMASM || USE_INTEL_SPEEDUP || \
            * WOLFSSL_AFALG_XILINX */

    /* Helpers for memory alignment */
    #ifndef XALIGNED
        #if defined(__GNUC__) || defined(__llvm__) || \
              defined(__IAR_SYSTEMS_ICC__)
            #define XALIGNED(x) __attribute__ ( (aligned (x)))
        #elif defined(__KEIL__)
            #define XALIGNED(x) __align(x)
        #elif defined(_MSC_VER)
            /* disable align warning, we want alignment ! */
            #pragma warning(disable: 4324)
            #define XALIGNED(x) __declspec (align (x))
        #else
            #define XALIGNED(x) /* null expansion */
        #endif
    #endif

    /* Only use alignment in wolfSSL/wolfCrypt if WOLFSSL_USE_ALIGN is set */
    #ifdef WOLFSSL_USE_ALIGN
        /* For IAR ARM the maximum variable alignment on stack is 8-bytes.
         * Variables declared outside stack (like static globals) can have
         * higher alignment. */
        #if defined(__ICCARM__)
            #define WOLFSSL_ALIGN(x) XALIGNED(8)
        #else
            #define WOLFSSL_ALIGN(x) XALIGNED(x)
        #endif
    #else
        #define WOLFSSL_ALIGN(x) /* null expansion */
    #endif

    #ifndef ALIGN8
        #define ALIGN8   WOLFSSL_ALIGN(8)
    #endif
    #ifndef ALIGN16
        #define ALIGN16  WOLFSSL_ALIGN(16)
    #endif
    #ifndef ALIGN32
        #define ALIGN32  WOLFSSL_ALIGN(32)
    #endif
    #ifndef ALIGN64
        #define ALIGN64  WOLFSSL_ALIGN(64)
    #endif
    #ifndef ALIGN128
        #define ALIGN128 WOLFSSL_ALIGN(128)
    #endif
    #ifndef ALIGN256
        #define ALIGN256 WOLFSSL_ALIGN(256)
    #endif

    #if !defined(PEDANTIC_EXTENSION)
        #if defined(__GNUC__)
            #define PEDANTIC_EXTENSION __extension__
        #else
            #define PEDANTIC_EXTENSION
        #endif
    #endif /* !PEDANTIC_EXTENSION */


    #ifndef TRUE
        #define TRUE  1
    #endif
    #ifndef FALSE
        #define FALSE 0
    #endif

    #ifdef SINGLE_THREADED
        #if defined(WC_32BIT_CPU) || defined(HAVE_STACK_SIZE)
            typedef void*        THREAD_RETURN;
        #else
            typedef unsigned int THREAD_RETURN;
        #endif
        typedef void*            THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(WOLFSSL_USER_THREADING)
        /* User can define user specific threading types
         *  THREAD_RETURN
         *  TREAD_TYPE
         *  WOLFSSL_THREAD
         * e.g.
         *  typedef unsigned int  THREAD_RETURN;
         *  typedef size_t        THREAD_TYPE;
         *  #define WOLFSSL_THREAD void
         *
         * User can also implement their own wolfSSL_NewThread(),
         * wolfSSL_JoinThread() and wolfSSL_Cond signaling if they want.
         * Otherwise, those functions are omitted.
        */
    #elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) || \
          defined(FREESCALE_MQX)
        typedef unsigned int  THREAD_RETURN;
        typedef int           THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(WOLFSSL_NUCLEUS)
        typedef unsigned int  THREAD_RETURN;
        typedef intptr_t      THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(WOLFSSL_TIRTOS)
        typedef void          THREAD_RETURN;
        #define WOLFSSL_THREAD_VOID_RETURN
        typedef Task_Handle   THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(WOLFSSL_ZEPHYR)
        typedef void            THREAD_RETURN;
        #define WOLFSSL_THREAD_VOID_RETURN
        typedef struct {
            /* Zephyr k_thread can be large, > 128 bytes. */
            struct k_thread* tid;
            k_thread_stack_t* threadStack;
        } THREAD_TYPE;
        #define WOLFSSL_THREAD
        extern void* wolfsslThreadHeapHint;
    #elif defined(NETOS)
        typedef UINT        THREAD_RETURN;
        typedef struct {
            TX_THREAD tid;
            void* threadStack;
        } THREAD_TYPE;
        #define WOLFSSL_THREAD
        #define INFINITE TX_WAIT_FOREVER
        #define WAIT_OBJECT_0 TX_NO_WAIT
    #elif defined(WOLFSSL_LINUXKM)
        typedef unsigned int  THREAD_RETURN;
        typedef size_t        THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(WOLFSSL_PTHREADS)
        #if defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= 1060 \
            && !defined(__ppc__)
            #include <dispatch/dispatch.h>
            typedef struct COND_TYPE {
                wolfSSL_Mutex mutex;
                dispatch_semaphore_t cond;
            } COND_TYPE;
        #else
            #include <pthread.h>
            typedef struct COND_TYPE {
                pthread_mutex_t mutex;
                pthread_cond_t cond;
            } COND_TYPE;
        #endif
        typedef void*         THREAD_RETURN;
        typedef pthread_t     THREAD_TYPE;
        #define WOLFSSL_COND
        #define WOLFSSL_THREAD
        #ifndef HAVE_SELFTEST
            #define WOLFSSL_THREAD_NO_JOIN
        #endif
    #elif defined(FREERTOS) && defined(WOLFSSL_ESPIDF)
        typedef void*          THREAD_RETURN;
        typedef pthread_t      THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(FREERTOS)
        typedef unsigned int   THREAD_RETURN;
        typedef TaskHandle_t   THREAD_TYPE;
        #define WOLFSSL_THREAD
    #elif defined(USE_WINDOWS_API)
        typedef unsigned      THREAD_RETURN;
        typedef uintptr_t     THREAD_TYPE;
        typedef struct COND_TYPE {
            wolfSSL_Mutex mutex;
            HANDLE cond;
        } COND_TYPE;
        #define WOLFSSL_COND
        #define INVALID_THREAD_VAL ((THREAD_TYPE)(INVALID_HANDLE_VALUE))
        #define WOLFSSL_THREAD __stdcall
        #if !defined(__MINGW32__)
            #define WOLFSSL_THREAD_NO_JOIN __cdecl
        #endif
    #elif defined(THREADX)
        typedef unsigned int   THREAD_RETURN;
        typedef TX_THREAD      THREAD_TYPE;
        #define WOLFSSL_THREAD
    #else
        typedef unsigned int  THREAD_RETURN;
        typedef size_t        THREAD_TYPE;
        #define WOLFSSL_THREAD __stdcall
    #endif


    #ifndef SINGLE_THREADED
        /* Necessary headers should already be included. */

        #ifndef INVALID_THREAD_VAL
            #define INVALID_THREAD_VAL ((THREAD_TYPE)(-1))
        #endif

        #ifndef WOLFSSL_THREAD_VOID_RETURN
            #define WOLFSSL_RETURN_FROM_THREAD(x) return (THREAD_RETURN)(x)
        #else
            #define WOLFSSL_RETURN_FROM_THREAD(x) \
                do { (void)(x); return; } while(0)
        #endif

        /* List of defines/types and what they mean:
         * THREAD_RETURN - return type of a thread callback
         * THREAD_TYPE - type that should be passed into thread handling API
         * INVALID_THREAD_VAL - a value that THREAD_TYPE can be checked against
         *                      to check if the value is an invalid thread
         * WOLFSSL_THREAD - attribute that should be used to declare thread
         *                  callbacks
         * WOLFSSL_THREAD_NO_JOIN - attribute that should be used to declare
         *                          thread callbacks that don't require cleanup
         * WOLFSSL_COND - defined if this system supports signaling
         * COND_TYPE - type that should be passed into the signaling API
         * WOLFSSL_THREAD_VOID_RETURN - defined if the thread callback has a
         *                              void return
         * WOLFSSL_RETURN_FROM_THREAD - define used to correctly return from a
         *                              thread callback
         * THREAD_CB - thread callback type for regular threading API
         * THREAD_CB_NOJOIN - thread callback type for threading API that don't
         *                    require cleanup
         *
         * Other defines/types are specific for the threading implementation
         */

        /* Internal wolfSSL threading interface. It does NOT need to be ported
         * during initial porting efforts. This is a very basic interface. Some
         * areas don't use this interface on purpose as they need more control
         * over threads.
         *
         * It is currently used for:
         * - CRL monitor
         * - Testing
         * - Entropy generation */

        /* We don't support returns from threads */
        typedef THREAD_RETURN (WOLFSSL_THREAD *THREAD_CB)(void* arg);
        WOLFSSL_API int wolfSSL_NewThread(THREAD_TYPE* thread,
            THREAD_CB cb, void* arg);
        #ifdef WOLFSSL_THREAD_NO_JOIN
            /* Create a thread that will be automatically cleaned up. We can't
             * return a handle/pointer to the new thread because there are no
             * guarantees for how long it will be valid. */
            typedef THREAD_RETURN (WOLFSSL_THREAD_NO_JOIN *THREAD_CB_NOJOIN)
                    (void* arg);
            WOLFSSL_API int wolfSSL_NewThreadNoJoin(THREAD_CB_NOJOIN cb,
                    void* arg);
        #endif
        WOLFSSL_API int wolfSSL_JoinThread(THREAD_TYPE thread);

        #ifdef WOLFSSL_COND
            WOLFSSL_API int wolfSSL_CondInit(COND_TYPE* cond);
            WOLFSSL_API int wolfSSL_CondFree(COND_TYPE* cond);
            WOLFSSL_API int wolfSSL_CondSignal(COND_TYPE* cond);
            WOLFSSL_API int wolfSSL_CondWait(COND_TYPE* cond);
            WOLFSSL_API int wolfSSL_CondStart(COND_TYPE* cond);
            WOLFSSL_API int wolfSSL_CondEnd(COND_TYPE* cond);
        #endif
    #else
        #define WOLFSSL_RETURN_FROM_THREAD(x) return (THREAD_RETURN)(x)
    #endif /* SINGLE_THREADED */

    #if defined(HAVE_STACK_SIZE)
        #define EXIT_TEST(ret) return (THREAD_RETURN)((size_t)(ret))
    #else
        #define EXIT_TEST(ret) return ret
    #endif


    #if (defined(__IAR_SYSTEMS_ICC__) && (__IAR_SYSTEMS_ICC__ > 8)) || \
         defined(__GNUC__)
        #define WOLFSSL_PACK __attribute__ ((packed))
    #else
        #define WOLFSSL_PACK
    #endif

    #ifndef __GNUC_PREREQ
        #if defined(__GNUC__) && defined(__GNUC_MINOR__)
            #define __GNUC_PREREQ(maj, min) \
                ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
        #else
            #define __GNUC_PREREQ(maj, min) (0) /* not GNUC */
        #endif
    #endif

    #if defined(__IAR_SYSTEMS_ICC__) || defined(__GNUC__)
        #define WC_NORETURN __attribute__((noreturn))
    #else
        #define WC_NORETURN
    #endif

    #if defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY) || \
        defined(WOLFSSL_DEBUG_MATH) || defined(DEBUG_WOLFSSL) || \
        defined(WOLFSSL_PUBLIC_MP) || defined(OPENSSL_EXTRA) || \
            (defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT))
        #undef  WC_MP_TO_RADIX
        #define WC_MP_TO_RADIX
    #endif

    #if defined(__GNUC__) && __GNUC__ > 5
        #define PRAGMA_GCC_DIAG_PUSH _Pragma("GCC diagnostic push")
        #define PRAGMA_GCC(str) _Pragma(str)
        #define PRAGMA_GCC_DIAG_POP _Pragma("GCC diagnostic pop")
        #define PRAGMA_DIAG_PUSH PRAGMA_GCC_DIAG_PUSH
        #define PRAGMA(str) PRAGMA_GCC(str)
        #define PRAGMA_DIAG_POP PRAGMA_GCC_DIAG_POP
    #else
        #define PRAGMA_GCC_DIAG_PUSH /* null expansion */
        #define PRAGMA_GCC(str) /* null expansion */
        #define PRAGMA_GCC_DIAG_POP /* null expansion */
    #endif

    #ifdef __clang__
        #define PRAGMA_CLANG_DIAG_PUSH _Pragma("clang diagnostic push")
        #define PRAGMA_CLANG(str) _Pragma(str)
        #define PRAGMA_CLANG_DIAG_POP _Pragma("clang diagnostic pop")
        #define PRAGMA_DIAG_PUSH PRAGMA_CLANG_DIAG_PUSH
        #define PRAGMA(str) PRAGMA_CLANG(str)
        #define PRAGMA_DIAG_POP PRAGMA_CLANG_DIAG_POP
    #else
        #define PRAGMA_CLANG_DIAG_PUSH /* null expansion */
        #define PRAGMA_CLANG(str) /* null expansion */
        #define PRAGMA_CLANG_DIAG_POP /* null expansion */
    #endif

    #ifndef PRAGMA_DIAG_PUSH
        #define PRAGMA_DIAG_PUSH /* null expansion */
    #endif
    #ifndef PRAGMA
        #define PRAGMA(str) /* null expansion */
    #endif
    #ifndef PRAGMA_DIAG_POP
        #define PRAGMA_DIAG_POP /* null expansion */
    #endif

    #define WC_CPP_CAT_(a, b) a ## b
    #define WC_CPP_CAT(a, b) WC_CPP_CAT_(a, b)
    #if defined(WC_NO_STATIC_ASSERT)
        #define wc_static_assert(expr) struct wc_static_assert_dummy_struct
        #define wc_static_assert2(expr, msg) wc_static_assert(expr)
    #elif !defined(wc_static_assert)
        #if (defined(__cplusplus) && (__cplusplus >= 201703L)) || \
               (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202311L)) || \
               (defined(_MSVC_LANG) && (_MSVC_LANG >= 201103L))
            /* native variadic static_assert() */
            #define wc_static_assert static_assert
            #ifndef wc_static_assert2
                #define wc_static_assert2 static_assert
            #endif
        #elif defined(_MSC_VER) && (__STDC_VERSION__ >= 201112L)
            /* native 2-argument static_assert() */
            #define wc_static_assert(expr) static_assert(expr, #expr)
            #ifndef wc_static_assert2
                #define wc_static_assert2(expr, msg) static_assert(expr, msg)
            #endif
        #elif !defined(__cplusplus) &&              \
                !defined(__STRICT_ANSI__) &&        \
                !defined(WOLF_C89) &&               \
                defined(__STDC_VERSION__) &&        \
                (__STDC_VERSION__ >= 201112L) &&    \
                ((defined(__GNUC__) &&              \
                  (__GNUC__ >= 5)) ||               \
                 defined(__clang__))
            /* native 2-argument _Static_assert() */
            #define wc_static_assert(expr) _Static_assert(expr, #expr)
            #ifndef wc_static_assert2
                #define wc_static_assert2(expr, msg) _Static_assert(expr, msg)
            #endif
        #else
            /* C89-compatible fallback */
            #define wc_static_assert(expr)                                     \
                struct WC_CPP_CAT(wc_static_assert_dummy_struct_L, __LINE__) { \
                    char t[(expr) ? 1 : -1];                                   \
                }
            #ifndef wc_static_assert2
                #define wc_static_assert2(expr, msg) wc_static_assert(expr)
            #endif
        #endif
    #elif !defined(wc_static_assert2)
         #define wc_static_assert2(expr, msg) wc_static_assert(expr)
    #endif

    #ifndef SAVE_VECTOR_REGISTERS
        #define SAVE_VECTOR_REGISTERS(fail_clause) WC_DO_NOTHING
    #endif
    #ifndef SAVE_VECTOR_REGISTERS2
        #define SAVE_VECTOR_REGISTERS2() 0
        #define SAVE_VECTOR_REGISTERS2_DOES_NOTHING
    #endif
    #ifndef CAN_SAVE_VECTOR_REGISTERS
        #define CAN_SAVE_VECTOR_REGISTERS() 1
        #define CAN_SAVE_VECTOR_REGISTERS_ALWAYS_TRUE
    #endif
    #ifndef WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL
        #define WC_DEBUG_SET_VECTOR_REGISTERS_RETVAL(x) WC_DO_NOTHING
    #endif
    #ifndef ASSERT_SAVED_VECTOR_REGISTERS
        #define ASSERT_SAVED_VECTOR_REGISTERS() WC_DO_NOTHING
    #endif
    #ifndef ASSERT_RESTORED_VECTOR_REGISTERS
        #define ASSERT_RESTORED_VECTOR_REGISTERS(fail_clause) WC_DO_NOTHING
    #endif
    #ifndef RESTORE_VECTOR_REGISTERS
        #define RESTORE_VECTOR_REGISTERS() WC_DO_NOTHING
    #endif

    #if FIPS_VERSION_GE(5,1)
        #define WC_SPKRE_F(x,y) wolfCrypt_SetPrivateKeyReadEnable_fips((x),(y))
        #define PRIVATE_KEY_LOCK() WC_SPKRE_F(0,WC_KEYTYPE_ALL)
        #define PRIVATE_KEY_UNLOCK() WC_SPKRE_F(1,WC_KEYTYPE_ALL)
    #else
        #define PRIVATE_KEY_LOCK() WC_DO_NOTHING
        #define PRIVATE_KEY_UNLOCK() WC_DO_NOTHING
    #endif


    #ifdef _MSC_VER
        /* disable buggy MSC warning (incompatible with clang-tidy
         * readability-avoid-const-params-in-decls)
         * "warning C4028: formal parameter x different from declaration"
         */
        #pragma warning(disable: 4028)
    #endif


    /* opaque math variable type */
    #if defined(USE_FAST_MATH)
        struct fp_int;
        #define MATH_INT_T struct fp_int
    #elif defined(USE_INTEGER_HEAP_MATH)
        struct mp_int;
        #define MATH_INT_T struct mp_int
    #else
        struct sp_int;
        #define MATH_INT_T struct sp_int
    #endif


    #ifdef __cplusplus
        }   /* extern "C" */
    #endif

#endif /* WOLF_CRYPT_TYPES_H */
