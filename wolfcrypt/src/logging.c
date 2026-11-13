/* logging.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef HAVE_WC_INTROSPECTION
#include <wolfssl/wolfcrypt/build_check.h>
#endif

#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
/* avoid adding WANT_READ and WANT_WRITE to error queue */
#include <wolfssl/error-ssl.h>
#endif

#ifdef WOLFSSL_FUNC_TIME
/* WARNING: This code is only to be used for debugging performance.
 *          The code is not thread-safe.
 *          Do not use WOLFSSL_FUNC_TIME in production code.
 */
static double wc_func_start[WC_FUNC_COUNT];
static double wc_func_time[WC_FUNC_COUNT] = { 0, };
static const char* wc_func_name[WC_FUNC_COUNT] = {
    "SendHelloRequest",
    "DoHelloRequest",
    "SendClientHello",
    "DoClientHello",
    "SendServerHello",
    "DoServerHello",
    "SendEncryptedExtensions",
    "DoEncryptedExtensions",
    "SendCertificateRequest",
    "DoCertificateRequest",
    "SendCertificate",
    "DoCertificate",
    "SendCertificateVerify",
    "DoCertificateVerify",
    "SendFinished",
    "DoFinished",
    "SendKeyUpdate",
    "DoKeyUpdate",
    "SendEarlyData",
    "DoEarlyData",
    "SendNewSessionTicket",
    "DoNewSessionTicket",
    "SendServerHelloDone",
    "DoServerHelloDone",
    "SendTicket",
    "DoTicket",
    "SendClientKeyExchange",
    "DoClientKeyExchange",
    "SendCertificateStatus",
    "DoCertificateStatus",
    "SendServerKeyExchange",
    "DoServerKeyExchange",
    "SendEarlyData",
    "DoEarlyData",
};

#include <sys/time.h>

/* WARNING: This function is not portable. */
static WC_INLINE double current_time(int reset)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    (void)reset;

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}
#endif /* WOLFSSL_FUNC_TIME */

#ifdef HAVE_WC_INTROSPECTION

const char *wolfSSL_configure_args(void) {
#ifdef LIBWOLFSSL_CONFIGURE_ARGS
  /* the spaces on either side are to make matching simple and efficient. */
  return " " LIBWOLFSSL_CONFIGURE_ARGS " ";
#else
  return NULL;
#endif
}

PEDANTIC_EXTENSION const char *wolfSSL_global_cflags(void) {
#ifdef LIBWOLFSSL_GLOBAL_CFLAGS
  /* the spaces on either side are to make matching simple and efficient. */
  return " " LIBWOLFSSL_GLOBAL_CFLAGS " ";
#else
  return NULL;
#endif
}

/* Names for the fingerprint, built from the same list that
 * wc_BuildConfig_Local() expands, so names cannot drift from their bits.
 * One table holds both kinds of entry. */
#define WC_BUILD_NAME_FEATURE 0
#define WC_BUILD_NAME_SIZE    1

typedef struct wc_BuildName {
    byte kind;  /* WC_BUILD_NAME_FEATURE or WC_BUILD_NAME_SIZE */
    byte a;     /* feature word, or size slot */
    byte b;     /* feature bit; 0 for a size slot */
    const char* name;
} wc_BuildName;

static const wc_BuildName wc_build_names[] = {
#define WC_BCF(w, b, n)     { WC_BUILD_NAME_FEATURE, (w), (b), #n },
#define WC_BCF_NO(w, b, n)  { WC_BUILD_NAME_FEATURE, (w), (b), #n },
#define WC_BCS(s, t)        { WC_BUILD_NAME_SIZE, (s), 0, #t },
#define WC_BCS_NO(s, t)     { WC_BUILD_NAME_SIZE, (s), 0, #t },
#define WC_BCS_UNKNOWN(s, t) { WC_BUILD_NAME_SIZE, (s), 0, #t },
#include <wolfssl/wolfcrypt/build_check_list.h>
#undef WC_BCF
#undef WC_BCF_NO
#undef WC_BCS
#undef WC_BCS_NO
#undef WC_BCS_UNKNOWN
    { 0, 0, 0, NULL }
};

static const char* wc_build_name(byte kind, word32 a, word32 b)
{
    int i;

    for (i = 0; wc_build_names[i].name != NULL; i++) {
        if ((wc_build_names[i].kind == kind) && (wc_build_names[i].a == a) &&
                (wc_build_names[i].b == b)) {
            return wc_build_names[i].name;
        }
    }
    return NULL;
}

/* Name of the macro behind a feature bit.
 *
 * word  [in]  Feature word index.
 * bit   [in]  Bit index in the word.
 * returns the macro name, or NULL for an unused or out of range bit.
 */
const char* wc_BuildConfigFeatureName(word32 word, word32 bit)
{
    if ((word >= (word32)WC_BUILD_FEATURE_WORDS) || (bit >= 32)) {
        return NULL;
    }
    return wc_build_name(WC_BUILD_NAME_FEATURE, word, bit);
}

/* Type recorded in a size slot.
 *
 * slot  [in]  Size slot index.
 * returns the type name, or NULL for an unused or out of range slot.
 */
const char* wc_BuildConfigSizeName(word32 slot)
{
    if (slot >= (word32)WC_BUILD_SIZE_COUNT) {
        return NULL;
    }
    return wc_build_name(WC_BUILD_NAME_SIZE, slot, 0);
}

/* Output state for wc_build_config_describe(): the optional caller buffer
 * and the item being formatted. Each difference is built in item (an item
 * longer than 95 characters is cut short; none in the list comes close),
 * then logged and/or appended to buf by wc_build_item_end(). No snprintf, so
 * this works on every platform the library does. */
typedef struct wc_BuildDescribe {
    char*  buf;
    word32 sz;
    word32 len;
    int    truncated;
    int    count;
    char   item[96];
    word32 itemLen;
} wc_BuildDescribe;

static void wc_build_item_str(wc_BuildDescribe* d, const char* str)
{
    while ((*str != '\0') && (d->itemLen < (word32)sizeof(d->item) - 1)) {
        d->item[d->itemLen++] = *str++;
    }
    d->item[d->itemLen] = '\0';
}

static void wc_build_item_dec(wc_BuildDescribe* d, word32 v)
{
    char tmp[11];
    int  i = (int)sizeof(tmp) - 1;

    tmp[i] = '\0';
    do {
        tmp[--i] = (char)('0' + (v % 10));
        v /= 10;
    } while ((v != 0) && (i > 0));
    wc_build_item_str(d, &tmp[i]);
}

static void wc_build_item_hex(wc_BuildDescribe* d, word32 v)
{
    static const char hexChars[] = "0123456789abcdef";
    char tmp[11];
    int  i;

    tmp[0] = '0';
    tmp[1] = 'x';
    for (i = 0; i < 8; i++) {
        tmp[2 + i] = hexChars[(v >> (28 - (4 * i))) & 0xf];
    }
    tmp[10] = '\0';
    wc_build_item_str(d, tmp);
}

/* Finish the current item: log it when doLog is set, and append it to the
 * output buffer, if any. When an item does not fit, the buffer is marked
 * truncated and ends in "..." (if it has room for one). */
static void wc_build_item_end(wc_BuildDescribe* d, int doLog)
{
    word32 need;
    word32 i;

    if (doLog) {
        WOLFSSL_MSG(d->item);
    }
    (void)doLog;

    if ((d->buf != NULL) && !d->truncated) {
        need = d->itemLen + ((d->count > 0) ? 2U : 0U);
        if (d->len + need + 1 <= d->sz) {
            if (d->count > 0) {
                d->buf[d->len++] = ';';
                d->buf[d->len++] = ' ';
            }
            for (i = 0; i < d->itemLen; i++) {
                d->buf[d->len++] = d->item[i];
            }
            d->buf[d->len] = '\0';
        }
        else {
            /* Mark the cut with "...", overwriting the tail if needed; a
             * buffer of under 4 bytes keeps only what already fit. */
            d->truncated = 1;
            if (d->sz >= 4) {
                if (d->len + 4 > d->sz) {
                    d->len = d->sz - 4;
                }
                d->buf[d->len++] = '.';
                d->buf[d->len++] = '.';
                d->buf[d->len++] = '.';
                d->buf[d->len] = '\0';
            }
        }
    }
    d->count++;
    d->itemLen = 0;
    d->item[0] = '\0';
}

/* Walk the differences between cfg (the caller's view) and lib (the
 * library's view), describing each one in d and, when doLog is set, in the
 * debug log. Feature bits with no name are reported by word and bit.
 *
 * returns a WC_BUILD_MISMATCH_* bitmask of what differed.
 */
static word32 wc_build_config_describe(const wc_BuildConfig* cfg,
    const wc_BuildConfig* lib, wc_BuildDescribe* d, int doLog)
{
    word32 diff = 0;
    word32 w;
    word32 b;
    const char* name;

    if (cfg->libVersionHex != lib->libVersionHex) {
        diff |= WC_BUILD_MISMATCH_VERSION;
        wc_build_item_str(d, "version: app=");
        wc_build_item_hex(d, cfg->libVersionHex);
        wc_build_item_str(d, " lib=");
        wc_build_item_hex(d, lib->libVersionHex);
        wc_build_item_end(d, doLog);
    }
    for (w = 0; w < (word32)WC_BUILD_FEATURE_WORDS; w++) {
        if (cfg->features[w] == lib->features[w]) {
            continue;
        }
        diff |= WC_BUILD_MISMATCH_FEATURES;
        for (b = 0; b < 32; b++) {
            if (((cfg->features[w] ^ lib->features[w]) & WC_BUILD_BIT(b)) ==
                    0) {
                continue;
            }
            name = wc_BuildConfigFeatureName(w, b);
            if (name != NULL) {
                wc_build_item_str(d, name);
            }
            else {
                wc_build_item_str(d, "feature word ");
                wc_build_item_dec(d, w);
                wc_build_item_str(d, " bit ");
                wc_build_item_dec(d, b);
            }
            wc_build_item_str(d, (cfg->features[w] & WC_BUILD_BIT(b)) ?
                ": app=on lib=off" : ": app=off lib=on");
            wc_build_item_end(d, doLog);
        }
    }
    for (w = 0; w < (word32)WC_BUILD_SIZE_COUNT; w++) {
        /* A side that could not see the type cannot be compared. */
        if ((cfg->sizes[w] == lib->sizes[w]) ||
                (cfg->sizes[w] == WC_BUILD_SIZE_UNKNOWN) ||
                (lib->sizes[w] == WC_BUILD_SIZE_UNKNOWN)) {
            continue;
        }
        diff |= WC_BUILD_MISMATCH_SIZES;
        name = wc_BuildConfigSizeName(w);
        if (name != NULL) {
            wc_build_item_str(d, "sizeof(");
            wc_build_item_str(d, name);
            wc_build_item_str(d, "): app=");
        }
        else {
            wc_build_item_str(d, "size slot ");
            wc_build_item_dec(d, w);
            wc_build_item_str(d, ": app=");
        }
        wc_build_item_dec(d, cfg->sizes[w]);
        wc_build_item_str(d, " lib=");
        wc_build_item_dec(d, lib->sizes[w]);
        wc_build_item_end(d, doLog);
    }
    if ((cfg->optionsHash != 0) && (lib->optionsHash != 0) &&
            (cfg->optionsHash != lib->optionsHash)) {
        diff |= WC_BUILD_MISMATCH_OPTIONS_HASH;
        wc_build_item_str(d, "options.h hash: app=");
        wc_build_item_hex(d, cfg->optionsHash);
        wc_build_item_str(d, " lib=");
        wc_build_item_hex(d, lib->optionsHash);
        wc_build_item_end(d, doLog);
    }
    return diff;
}

/* The version 1 fields are fixed; a later version only appends. */
wc_static_assert(sizeof(wc_BuildConfig) == WC_BUILD_CONFIG_V1_SZ);

/* Check that a caller's struct has a layout this library can read: version 1
 * or later, and covering at least the version 1 fields.  A smaller struct
 * than this library's (an older caller) is fine: the comparison only reads
 * the version 1 fields, which every layout has. */
static int wc_build_config_valid(const wc_BuildConfig* cfg)
{
    return (cfg != NULL) &&
        (cfg->structSz >= WC_BUILD_CONFIG_V1_SZ) &&
        (cfg->cfgVersion >= 1);
}

/* Report the build configuration this library was compiled with.
 *
 * cfg    [out]  Filled with the library's configuration fingerprint.
 * cfgSz  [in]   Size of the caller's *cfg in bytes, normally sizeof(*cfg).
 *               At most this many bytes are written; cfg->structSz is set to
 *               the number written.
 * returns 0 on success, BAD_FUNC_ARG when cfg is NULL or cfgSz is less than
 *         WC_BUILD_CONFIG_V1_SZ.
 */
int wc_GetBuildConfig(wc_BuildConfig* cfg, word32 cfgSz)
{
    wc_BuildConfig lib;

    if ((cfg == NULL) || (cfgSz < WC_BUILD_CONFIG_V1_SZ)) {
        return BAD_FUNC_ARG;
    }
    if (cfgSz > (word32)sizeof(lib)) {
        cfgSz = (word32)sizeof(lib);
    }
    wc_BuildConfig_Local(&lib);
    lib.structSz = cfgSz;
    XMEMCPY(cfg, &lib, cfgSz);
    return 0;
}

/* Compare a caller's build configuration with the library's.
 *
 * Only fields present in both layouts are compared: cfg->structSz must cover
 * at least the version 1 layout, and a larger caller struct (newer header) is
 * accepted with the fields this library does not know about ignored.
 * The options hashes are only compared when both are non-zero. With
 * DEBUG_WOLFSSL, each difference is logged by name.
 *
 * cfg       [in]   Caller's configuration (see wc_BuildConfig_Local()).
 * mismatch  [out]  Optional; receives a WC_BUILD_MISMATCH_* bitmask.
 * returns 0 when the configurations match, BUILD_CONFIG_MISMATCH_E when they
 *         differ, BAD_FUNC_ARG on NULL cfg or an unrecognized layout.
 */
int wc_CompareBuildConfig(const wc_BuildConfig* cfg, word32* mismatch)
{
    wc_BuildConfig lib;
    wc_BuildDescribe d;
    word32 diff;
    int doLog = 0;

    if (mismatch != NULL) {
        *mismatch = 0;
    }
    if (!wc_build_config_valid(cfg)) {
        return BAD_FUNC_ARG;
    }

    wc_BuildConfig_Local(&lib);
    XMEMSET(&d, 0, sizeof(d));
#if defined(DEBUG_WOLFSSL) && !defined(WOLFSSL_DEBUG_ERRORS_ONLY)
    doLog = 1;
#endif
    diff = wc_build_config_describe(cfg, &lib, &d, doLog);

    if (mismatch != NULL) {
        *mismatch = diff;
    }
    return (diff == 0) ? 0 : BUILD_CONFIG_MISMATCH_E;
}

/* Describe how a caller's build configuration differs from the library's.
 *
 * cfg    [in]   Caller's configuration (see wc_BuildConfig_Local()).
 * buf    [out]  Receives a NUL-terminated, "; "-separated description.
 * bufSz  [in]   Size of buf in bytes.
 * returns the length of the description (0 when the configurations match),
 *         BUFFER_E when buf is too small (it then holds the items that fit,
 *         ending in "..." when bufSz is at least 4), BAD_FUNC_ARG on NULL
 *         arguments, a zero bufSz or an unrecognized layout.
 */
int wc_BuildConfigMismatchString(const wc_BuildConfig* cfg, char* buf,
    word32 bufSz)
{
    wc_BuildConfig lib;
    wc_BuildDescribe d;

    if ((buf == NULL) || (bufSz == 0)) {
        return BAD_FUNC_ARG;
    }
    buf[0] = '\0';
    if (!wc_build_config_valid(cfg)) {
        return BAD_FUNC_ARG;
    }

    wc_BuildConfig_Local(&lib);
    XMEMSET(&d, 0, sizeof(d));
    d.buf = buf;
    d.sz  = bufSz;
    (void)wc_build_config_describe(cfg, &lib, &d, 0);

    if (d.truncated) {
        return BUFFER_E;
    }
    return (int)d.len;
}

#endif /* HAVE_WC_INTROSPECTION */

#ifdef HAVE_STACK_SIZE_VERBOSE

THREAD_LS_T unsigned char *StackSizeCheck_myStack = NULL;
THREAD_LS_T size_t StackSizeCheck_stackSize = 0;
THREAD_LS_T size_t StackSizeCheck_stackSizeHWM = 0;
THREAD_LS_T size_t *StackSizeCheck_stackSizeHWM_ptr = 0;
THREAD_LS_T void *StackSizeCheck_stackOffsetPointer = 0;

#endif /* HAVE_STACK_SIZE_VERBOSE */

#if defined(DEBUG_WOLFSSL) || \
    (defined(WOLFSSL_DEBUG_CERTS) && !defined(NO_WOLFSSL_DEBUG_CERTS))

/* Set these to default values initially. */
static wolfSSL_Logging_cb LogFunction = NULL;
#ifndef WOLFSSL_LOGGINGENABLED_DEFAULT
#define WOLFSSL_LOGGINGENABLED_DEFAULT 0
#endif
static int loggingEnabled = WOLFSSL_LOGGINGENABLED_DEFAULT;
#ifndef WOLFSSL_CERT_LOG_ENABLED_DEFAULT
#define WOLFSSL_CERT_LOG_ENABLED_DEFAULT 0
#endif
#ifndef NO_WOLFSSL_DEBUG_CERTS
static int loggingCertEnabled = WOLFSSL_CERT_LOG_ENABLED_DEFAULT;
#endif
THREAD_LS_T const char* log_prefix = NULL;

#endif /* DEBUG_WOLFSSL || WOLFSSL_DEBUG_CERTS */

int wolfSSL_CertDebugging_ON(void)
{
    /* Certificate debugging is also a subset of full debugging */
#if defined(WOLFSSL_DEBUG_CERTS) || defined(DEBUG_WOLFSSL)
    #if defined(NO_WOLFSSL_DEBUG_CERTS)
        return NOT_COMPILED_IN;
    #else
        loggingCertEnabled = 1;
    #endif
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}

int wolfSSL_CertDebugging_OFF(void)
{
#if defined(WOLFSSL_DEBUG_CERTS) || defined(DEBUG_WOLFSSL)
    #if defined(NO_WOLFSSL_DEBUG_CERTS)
        return NOT_COMPILED_IN;
    #else
        loggingCertEnabled = 0;
    #endif
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}

/* allow this to be set to NULL, so logs can be redirected to default output */
int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function)
{
#ifdef DEBUG_WOLFSSL
    LogFunction = log_function;
    return 0;
#else
    (void)log_function;
    return NOT_COMPILED_IN;
#endif
}

/* allow this to be set to NULL, so logs can be redirected to default output */
wolfSSL_Logging_cb wolfSSL_GetLoggingCb(void)
{
#ifdef DEBUG_WOLFSSL
    return LogFunction;
#else
    return NULL;
#endif
}


int wolfSSL_Debugging_ON(void)
{
#ifdef DEBUG_WOLFSSL
    loggingEnabled = 1;
    #ifndef NO_WOLFSSL_DEBUG_CERTS
        /* Certificate debugging is enabled by default during DEBUG_WOLFSSL,
         * unless explicitly disabled with NO_WOLFSSL_DEBUG_CERTS */
        loggingCertEnabled = 1;
    #endif
    return 0;
#else
    return NOT_COMPILED_IN;
#endif /* DEBUG_WOLFSSL */
}


void wolfSSL_Debugging_OFF(void)
{
#ifdef DEBUG_WOLFSSL
    loggingEnabled = 0;
    #ifndef NO_WOLFSSL_DEBUG_CERTS
        loggingCertEnabled = 0;
    #endif
#endif
}

void wolfSSL_SetLoggingPrefix(const char* prefix)
{
#if defined(DEBUG_WOLFSSL) || \
   (defined(WOLFSSL_DEBUG_CERTS) && !defined(NO_WOLFSSL_DEBUG_CERTS))
    log_prefix = prefix;
#else
    (void)prefix;
#endif
}

#ifdef WOLFSSL_FUNC_TIME
/* WARNING: This code is only to be used for debugging performance.
 *          The code is not thread-safe.
 *          Do not use WOLFSSL_FUNC_TIME in production code.
 */
void WOLFSSL_START(int funcNum)
{
    if (funcNum < WC_FUNC_COUNT) {
        double now = current_time(0) * 1000.0;
    #ifdef WOLFSSL_FUNC_TIME_LOG
        WOLFSSL_DEBUG_PRINTF("%17.3f: START - %s\n",
                             now, wc_func_name[funcNum]);
    #endif
        wc_func_start[funcNum] = now;
    }
}

void WOLFSSL_END(int funcNum)
{
    if (funcNum < WC_FUNC_COUNT) {
        double now = current_time(0) * 1000.0;
        wc_func_time[funcNum] += now - wc_func_start[funcNum];
    #ifdef WOLFSSL_FUNC_TIME_LOG
        WOLFSSL_DEBUG_PRINTF("%17.3f: END   - %s\n",
                             now, wc_func_name[funcNum]);
    #endif
    }
}

void WOLFSSL_TIME(int count)
{
    int i;
    double avg, total = 0;

    for (i = 0; i < WC_FUNC_COUNT; i++) {
        if (wc_func_time[i] > 0) {
            avg = wc_func_time[i] / count;
            WOLFSSL_DEBUG_PRINTF("%8.3f ms: %s\n", avg, wc_func_name[i]);
            total += avg;
        }
    }
    WOLFSSL_DEBUG_PRINTF("%8.3f ms\n", total);
}
#endif

#if defined(DEBUG_WOLFSSL) || \
    (defined(WOLFSSL_DEBUG_CERTS) && !defined(NO_WOLFSSL_DEBUG_CERTS))

#ifdef HAVE_STACK_SIZE_VERBOSE
#include <wolfssl/wolfcrypt/mem_track.h>
#endif

static void wolfssl_log(const int logLevel, const char* const file_name,
                        int line_number, const char* const logMessage)
{
    (void)file_name;
    (void)line_number;
    if (LogFunction)
        LogFunction(logLevel, logMessage);
    else {
#if defined(WOLFSSL_USER_LOG)
        WOLFSSL_USER_LOG(logMessage);
#elif defined(WOLFSSL_DEBUG_PRINTF_FN)
    #ifdef WOLFSSL_MDK_ARM
        fflush(stdout);
    #endif
    /* see settings.h for platform-specific line endings */
    #ifndef WOLFSSL_DEBUG_LINE_ENDING
        #define WOLFSSL_DEBUG_LINE_ENDING "\n"
    #endif
        if (log_prefix != NULL) {
            if (file_name != NULL) {
                WOLFSSL_DEBUG_PRINTF_FN(WOLFSSL_DEBUG_PRINTF_FIRST_ARGS
                        "[%s]: [%s L %d] %s" WOLFSSL_DEBUG_LINE_ENDING,
                        log_prefix, file_name, line_number, logMessage);
            }
            else {
                WOLFSSL_DEBUG_PRINTF_FN(WOLFSSL_DEBUG_PRINTF_FIRST_ARGS
                   "[%s]: %s" WOLFSSL_DEBUG_LINE_ENDING, log_prefix, logMessage);
            } /* file_name check */
        }
        else {
            if (file_name != NULL) {
                WOLFSSL_DEBUG_PRINTF_FN(WOLFSSL_DEBUG_PRINTF_FIRST_ARGS
                        "[%s L %d] %s" WOLFSSL_DEBUG_LINE_ENDING,
                        file_name, line_number, logMessage);
            }
            else {
                WOLFSSL_DEBUG_PRINTF_FN(WOLFSSL_DEBUG_PRINTF_FIRST_ARGS
                        "%s" WOLFSSL_DEBUG_LINE_ENDING, logMessage);
            } /* file_name check */
        } /* log_prefix check */
    #ifdef WOLFSSL_MDK_ARM
        fflush(stdout);
    #endif
#elif defined(ARDUINO)
        wolfSSL_Arduino_Serial_Print(logMessage);
#elif defined(WOLFSSL_UTASKER)
        fnDebugMsg((char*)logMessage);
        fnDebugMsg("\r\n");
#elif defined(STACK_SIZE_CHECKPOINT_MSG) && \
      defined(HAVE_STACK_SIZE_VERBOSE) && defined(HAVE_STACK_SIZE_VERBOSE_LOG)
        STACK_SIZE_CHECKPOINT_MSG(logMessage);
#else
    #error No log method defined.
#endif
    }
}

#ifndef WOLFSSL_DEBUG_ERRORS_ONLY

/* Certificate debugging available with either regular debugging
 * DEBUG_WOLFSSL or just certificate debugging: WOLFSSL_DEBUG_CERTS */
#if (defined(WOLFSSL_DEBUG_CERTS) || defined(DEBUG_WOLFSSL)) && \
    !defined(NO_WOLFSSL_DEBUG_CERTS)
    #include <stdarg.h> /* for var args */

    #ifndef WOLFSSL_MSG_CERT_BUF_SZ
        #define WOLFSSL_MSG_CERT_BUF_SZ 140
    #endif

    int WOLFSSL_MSG_CERT(const char* msg)
    {
        /* Regular debug may have been compiled out */
        (void)loggingEnabled;

        if ((msg != NULL) && (loggingCertEnabled != 0)) {
            wolfssl_log(CERT_LOG, NULL, 0, msg);
        }
        return 0;
    }

    #ifdef XVSNPRINTF
    #ifdef __clang__
    /* tell clang argument 1 is format */
    __attribute__((__format__ (__printf__, 1, 0)))
    #endif
    int WOLFSSL_MSG_CERT_EX(const char* fmt, ...)
    {
        /* Certificate logging output may have large messages */
    #ifdef WOLFSSL_SMALL_STACK
        char*  msg;
        msg = (char*)XMALLOC(WOLFSSL_MSG_CERT_BUF_SZ, NULL,
                             DYNAMIC_TYPE_TMP_BUFFER);
        if (msg == NULL) {
            return MEMORY_E;
        }
    #else
        char msg[WOLFSSL_MSG_CERT_BUF_SZ];
    #endif
        int written;
        va_list args;
        va_start(args, fmt);
        /* Assume zero-terminated msg, len less than WOLFSSL_MSG_CERT_BUF_SZ */
        written = XVSNPRINTF(msg, WOLFSSL_MSG_CERT_BUF_SZ, fmt, args);
        va_end(args);
        if ((written > 0) && (loggingCertEnabled != 0)) {
            wolfssl_log(INFO_LOG, NULL, 0, msg);
        }
    WC_FREE_VAR_EX(msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return 0;
    } /* WOLFSSL_MSG_CERT_EX */
    #endif /* XVSNPRINTF */

#else /* (!WOLFSSL_DEBUG_CERTS && !DEBUG_WOLFSSL) || NO_WOLFSSL_DEBUG_CERTS */

    #ifdef WOLF_NO_VARIADIC_MACROS
        #ifdef  __WATCOMC__
            /* Do-nothing implementation in header for OW Open Watcom V2 */
        #else
            int WOLFSSL_MSG_CERT(const char* msg)
            {
                (void)msg;
                return NOT_COMPILED_IN;
            }
           int WOLFSSL_MSG_CERT_EX(const char* fmt, ...)
           {
               (void)fmt;
               return NOT_COMPILED_IN;
           }
        #endif
    #else
        /* using a macro, see logging.h */
    #endif
#endif /* (!WOLFSSL_DEBUG_CERTS && !DEBUG_WOLFSSL) || NO_WOLFSSL_DEBUG_CERTS */

#if defined(XVSNPRINTF) && !defined(NO_WOLFSSL_MSG_EX)
#if defined(WOLFSSL_BSDKM)
    #include <machine/stdarg.h> /* for var args */
#else
    #include <stdarg.h> /* for var args */
#endif /* WOLFSSL_BSDKM */

#ifndef WOLFSSL_MSG_EX_BUF_SZ
#define WOLFSSL_MSG_EX_BUF_SZ 100
#endif

#if !defined(WOLFSSL_MSG_EX) && defined(DEBUG_WOLFSSL)
#ifdef __clang__
/* tell clang argument 1 is format */
__attribute__((__format__ (__printf__, 1, 0)))
#endif
void WOLFSSL_MSG_EX(const char* fmt, ...)
{
    if (loggingEnabled) {
        char msg[WOLFSSL_MSG_EX_BUF_SZ];
        int written;
        va_list args;
        va_start(args, fmt);
        written = XVSNPRINTF(msg, sizeof(msg), fmt, args);
        va_end(args);
        if (written > 0)
            wolfssl_log(INFO_LOG, NULL, 0, msg);
    }
}
#endif

#ifdef WOLFSSL_DEBUG_CODEPOINTS
void WOLFSSL_MSG_EX2(const char *file, int line, const char* fmt, ...)
{
    if (loggingEnabled) {
        char msg[WOLFSSL_MSG_EX_BUF_SZ];
        int written;
        va_list args;
        va_start(args, fmt);
        written = XVSNPRINTF(msg, sizeof(msg), fmt, args);
        va_end(args);
        if (written > 0)
            wolfssl_log(INFO_LOG, file, line, msg);
    }
}
#endif /* WOLFSSL_DEBUG_CODEPOINTS */

#else
    /* We need a do-nothing function when variadic macros not available */
    #ifdef WOLF_NO_VARIADIC_MACROS
        /* See header for same-name, do nothing functions */
    #else
        /* See header for same-name, do nothing macros */
    #endif
#endif /* XVSNPRINTF && !NO_WOLFSSL_MSG_EX */

#ifndef WOLFSSL_MSG
void WOLFSSL_MSG(const char* msg)
{
    if (loggingEnabled)
        wolfssl_log(INFO_LOG, NULL, 0, msg);
}
#endif

#ifdef WOLFSSL_DEBUG_CODEPOINTS
void WOLFSSL_MSG2(const char *file, int line, const char* msg)
{
    if (loggingEnabled)
        wolfssl_log(INFO_LOG, file, line, msg);
}
#endif

#ifndef WOLFSSL_BUFFER
#ifndef LINE_LEN
#define LINE_LEN 16
#endif
void WOLFSSL_BUFFER(const byte* buffer, word32 length)
{
    int i, buflen = (int)length;
    char line[(LINE_LEN * 4) + 3]; /* \t00..0F | chars...chars\0 */

    if (!loggingEnabled) {
        return;
    }

    if (!buffer) {
        wolfssl_log(INFO_LOG, NULL, 0, "\tNULL");
        return;
    }

    while (buflen > 0) {
        int bufidx = 0;
        if (XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "\t")
            >= (int)sizeof(line) - bufidx)
        {
            goto errout;
        }
        bufidx++;

        for (i = 0; i < LINE_LEN; i++) {
            if (i < buflen) {
                if (XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "%02x ",
                              buffer[i]) >= (int)sizeof(line) - bufidx)
                {
                    goto errout;
                }
            }
            else {
                if (XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "   ")
                    >= (int)sizeof(line) - bufidx)
                {
                    goto errout;
                }
            }
            bufidx += 3;
        }

        if (XSNPRINTF(&line[bufidx], sizeof(line)-bufidx, "| ")
            >= (int)sizeof(line) - bufidx)
        {
            goto errout;
        }
        bufidx++;

        for (i = 0; i < LINE_LEN; i++) {
            if (i < buflen) {
                if (XSNPRINTF(&line[bufidx], sizeof(line)-bufidx,
                              "%c", 31 < buffer[i] && buffer[i] < 127
                              ? buffer[i]
                              : '.')
                    >= (int)sizeof(line) - bufidx)
                {
                    goto errout;
                }
                bufidx++;
            }
        }

        wolfssl_log(INFO_LOG, NULL, 0, line);
        buffer += LINE_LEN;
        buflen -= LINE_LEN;
    }

    return;

errout:

    wolfssl_log(INFO_LOG, NULL, 0, "\t[Buffer error while rendering]");
}
#endif /* WOLFSSL_BUFFER */

#ifndef WOLFSSL_ENTER
void WOLFSSL_ENTER(const char* msg)
{
    if (loggingEnabled) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        if (XSNPRINTF(buffer, sizeof(buffer), "wolfSSL Entering %s", msg)
            >= (int)sizeof(buffer))
        {
            buffer[sizeof(buffer) - 1] = 0;
        }
        wolfssl_log(ENTER_LOG, NULL, 0, buffer);
    }
}
#endif /* WOLFSSL_ENTER */

#ifdef WOLFSSL_DEBUG_CODEPOINTS
void WOLFSSL_ENTER2(const char *file, int line, const char* msg)
{
    if (loggingEnabled) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        if (XSNPRINTF(buffer, sizeof(buffer), "wolfSSL Entering %s", msg)
            >= (int)sizeof(buffer))
        {
            buffer[sizeof(buffer) - 1] = 0;
        }
        wolfssl_log(ENTER_LOG, file, line, buffer);
    }
}
#endif /* WOLFSSL_DEBUG_CODEPOINTS */

#ifndef WOLFSSL_LEAVE
void WOLFSSL_LEAVE(const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        if (XSNPRINTF(buffer, sizeof(buffer), "wolfSSL Leaving %s, return %d",
                      msg, ret)
            >= (int)sizeof(buffer))
        {
            buffer[sizeof(buffer) - 1] = 0;
        }
        wolfssl_log(LEAVE_LOG, NULL, 0, buffer);
    }
}
#endif /* WOLFSSL_LEAVE */

#ifdef WOLFSSL_DEBUG_CODEPOINTS
void WOLFSSL_LEAVE2(const char *file, int line, const char* msg, int ret)
{
    if (loggingEnabled) {
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        if (XSNPRINTF(buffer, sizeof(buffer), "wolfSSL Leaving %s, return %d",
                      msg, ret)
            >= (int)sizeof(buffer))
        {
            buffer[sizeof(buffer) - 1] = 0;
        }
        wolfssl_log(LEAVE_LOG, file, line, buffer);
    }
}
#endif

#ifdef WOLFSSL_DEBUG_CODEPOINTS
    /* restore the wrappers */
    #define WOLFSSL_MSG(msg) WOLFSSL_MSG2(__FILE__, __LINE__, msg)
    #define WOLFSSL_ENTER(msg) WOLFSSL_ENTER2(__FILE__, __LINE__, msg)
    #define WOLFSSL_LEAVE(msg, ret) WOLFSSL_LEAVE2(__FILE__, __LINE__, msg, ret)
    #ifdef XVSNPRINTF
/*        #define WOLFSSL_MSG_EX(fmt, args...) \
                WOLFSSL_MSG_EX2(__FILE__, __LINE__, fmt, ## args)
    */
    #endif
#endif

#ifndef WOLFSSL_IS_DEBUG_ON
int WOLFSSL_IS_DEBUG_ON(void)
{
    return loggingEnabled;
}
#endif /* WOLFSSL_IS_DEBUG_ON */
#endif /* !WOLFSSL_DEBUG_ERRORS_ONLY */

#else
    /* !(DEBUG_WOLFSSL || (WOLFSSL_DEBUG_CERTS && !NO_WOLFSSL_DEBUG_CERTS)) */
    /*
     * Create some no-op functions for compilers without variadic macros,
     * other than Open Watcom V2.
     */
    #ifdef WOLF_NO_VARIADIC_MACROS
        /* no debug and cannot use variadic macros */
        #ifdef __WATCOMC__
            /* see logging.h for no-op Watcom implementation */
        #else
            int WOLFSSL_MSG_CERT(const char* msg)
            {
                (void)msg;
                return NOT_COMPILED_IN;
            }

            int WOLFSSL_MSG_CERT_EX(const char* fmt, ...)
            {
                (void)fmt;
                return NOT_COMPILED_IN;
            }
        #endif
    #else
        /* see logging.h for variadic macros */
    #endif
#endif /* DEBUG_WOLFSSL || (WOLFSSL_DEBUG_CERTS && !NO_WOLFSSL_DEBUG_CERTS) */

/* Final catch for no-op WOLFSSL_MSG_EX needing implementation */
#ifdef __WATCOMC__
    /* See no-op implementation as needed in logging.h */
#else
    #ifdef DEBUG_WOLFSSL
        /* The empty no-op function is not needed when debugging */
    #else
        #if defined(HAVE_WOLFSSL_MSG_EX) || defined(WOLF_NO_VARIADIC_MACROS)
            void WOLFSSL_MSG_EX(const char* fmt, ...)
            {
                (void)fmt;
            }
        #else
            /* See macro in header */
        #endif
    #endif
#endif



#if defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE) || defined(HAVE_MEMCACHED)

#ifdef WOLFSSL_HAVE_ERROR_QUEUE

#ifdef ERROR_QUEUE_PER_THREAD
/* Keep the error queue in thread-local-storage. The only ways this
 * API can deliver meaningful semantics in a multi-threaded setup.
 */
#ifndef ERROR_QUEUE_MAX
/* Same as OpenSSL v1.1.x limit, note that this is per thread */
#define ERROR_QUEUE_MAX 16
#endif

struct wc_error_entry {
    char   reason[WOLFSSL_MAX_ERROR_SZ];
    char   file[WOLFSSL_MAX_ERROR_SZ];
    int    line;
    int    err;
};

struct wc_error_queue {
    struct wc_error_entry entries[ERROR_QUEUE_MAX];
    size_t head_idx;
    size_t count;
};

/* The complete queue in a thread local without allocations */
static THREAD_LS_T struct wc_error_queue wc_errors;

/* Using thread-local-storage, we do not need a mutex. */
#define ERRQ_LOCK()            0
#define ERRQ_UNLOCK()          (void)0

/**
 * Given a relative index (from head of the error list), return
 * the absolute index in the `wc_errors->entries` array for
 * the entry or -1 if no such entry exists/is present.
 */
static int get_abs_idx(int relative_idx)
{
    if ((wc_errors.count == 0) || (relative_idx >= (int)wc_errors.count)) {
        return -1;
    }
    if (relative_idx < 0) {
        return (int)((wc_errors.head_idx + wc_errors.count - 1)
                      % ERROR_QUEUE_MAX);
    }
    return (int)((wc_errors.head_idx + (size_t)relative_idx) % ERROR_QUEUE_MAX);
}

/**
 * Return the error entry at the given relative index, if
 * it exists, e.g. `relative_idx` is in a valid range.
 */
static struct wc_error_entry *get_entry(int relative_idx)
{
    int abs_idx;

    abs_idx = get_abs_idx(relative_idx);
    if (abs_idx < 0) {
        return NULL;
    }
    return &wc_errors.entries[abs_idx];
}

/**
 * Return the error code in the given error `entry` and populate
 * `file`, `reason` and `line` with its values.
 * `entry` may be NULL, in which case BAD_STATE_E is returned.
 */
static int pass_entry(struct wc_error_entry *entry,
                      const char **file, const char **reason,
                      int *line)
{
    if (entry == NULL) {
        WOLFSSL_MSG("No Error found in queue");
        return BAD_STATE_E;
    }
    if (file != NULL) {
        *file = entry->file;
    }
    if (reason != NULL) {
        *reason = entry->reason;
    }
    if (line != NULL) {
        *line = entry->line;
    }
    return entry->err;
}

/**
 * Assign entry with values, resets all previously present values.
 */
static void set_entry(struct wc_error_entry *entry, int error,
                      const char *file, const char *reason, int line)
{
    size_t sz;

    XMEMSET(entry, 0, sizeof(struct wc_error_entry));
    entry->err = error;

    entry->line  = line;
    sz = XSTRLEN(reason);
    if (sz > WOLFSSL_MAX_ERROR_SZ - 1) {
        sz = WOLFSSL_MAX_ERROR_SZ - 1;
    }
    if (sz > 0) {
        XMEMCPY(entry->reason, reason, sz);
        entry->reason[WOLFSSL_MAX_ERROR_SZ - 1] = '\0';
    }

    sz = XSTRLEN(file);
    if (sz > WOLFSSL_MAX_ERROR_SZ - 1) {
        sz = WOLFSSL_MAX_ERROR_SZ - 1;
    }
    if (sz > 0) {
        XMEMCPY(entry->file, file, sz);
        entry->file[WOLFSSL_MAX_ERROR_SZ - 1]  = '\0';
    }
}

/* Internal function that is called by wolfCrypt_Init() */
int wc_LoggingInit(void)
{
    return 0;
}

/* internal function that is called by wolfCrypt_Cleanup */
int wc_LoggingCleanup(void)
{
    /* clear logging entries */
    wc_ClearErrorNodes();
    return 0;
}

/**
 * Get the values from the HEAD of the ERR queue, but keep it in place.
 * If the queue is empty, return BAD_STATE_E.
 */
int wc_PeekErrorNode(int idx, const char **file, const char **reason,
                     int *line)
{
    return pass_entry(get_entry(idx), file, reason, line);
}

/**
 * Get the values from the HEAD of the ERR queue and remove it.
 * If the queue is empty, return BAD_STATE_E.
 */
int wc_PullErrorNode(const char **file, const char **reason, int *line)
{
    struct wc_error_entry *entry;
    int ret;

    entry = get_entry(0);
    ret = pass_entry(entry, file, reason, line);

    if (entry != NULL) {
      wc_RemoveErrorNode(0);
    }
    return ret;
}

/* create new error node and add it to the queue
 * buffers are assumed to be of size WOLFSSL_MAX_ERROR_SZ for this internal
 * function. */
int wc_AddErrorNode(int error, int line, char* reason, char* file)
{
    struct wc_error_entry *entry;
    size_t idx;

    if (wc_errors.count >= ERROR_QUEUE_MAX) {
        WOLFSSL_MSG("Error queue is full, at ERROR_QUEUE_MAX");
        return MEMORY_E;
    }

    idx = (wc_errors.head_idx + wc_errors.count) % ERROR_QUEUE_MAX;
    entry = &wc_errors.entries[idx];
    set_entry(entry, error, file, reason, line);
    ++wc_errors.count;

    return 0;
}

/**
 * Remove the entry at relative position `relative_idx` from the ERR queue.
 * For `relative_idx == 0` it removes the queue's head entry, for -1
 * it removes the last entry in the queue.
 */
void wc_RemoveErrorNode(int relative_idx)
{
    int abs_idx = get_abs_idx(relative_idx);

    if (abs_idx >= 0) {
        size_t move_count;
        if (abs_idx >= (int)wc_errors.head_idx) {
            /* removed entry sits "above" head (or is head),
             * move entries below it "up" */
            move_count = (size_t)abs_idx - wc_errors.head_idx;
            if (move_count > 0) {
                XMEMMOVE(&wc_errors.entries[wc_errors.head_idx + 1],
                         &wc_errors.entries[wc_errors.head_idx],
                         sizeof(wc_errors.entries[0]) * move_count);
            }
            wc_errors.head_idx = (wc_errors.head_idx + 1) % ERROR_QUEUE_MAX;
            --wc_errors.count;
        }
        else {
            /* removed entry sits "below" head (wrap around),
             * move entries above it "down" */
            int last_idx = get_abs_idx(-1);
            if (last_idx >= abs_idx) {  /* this SHOULD always be true */
                move_count = (size_t)(last_idx - abs_idx);
                if (move_count > 0) {
                    XMEMMOVE(&wc_errors.entries[abs_idx],
                             &wc_errors.entries[abs_idx + 1],
                             sizeof(wc_errors.entries[0]) * move_count);
                }
                --wc_errors.count;
            }
        }
    }
}

/**
 * Clear the ERR queue.
 */
void wc_ClearErrorNodes(void)
{
    if (wc_errors.count > 0) {
        XMEMSET(&wc_errors, 0, sizeof(wc_errors));
    }
}

int wc_SetLoggingHeap(void* h)
{
    (void)h;
    return 0;
}

int wc_ERR_remove_state(void)
{
    wc_ClearErrorNodes();
    return 0;
}

/**
 * Get the first entry's values in the ERR queue that is not filtered
 * by the provided `ignore_err` callback. All ignored entries are removed,
 * making the returned entry the head of the ERR queue afterwards.
 *
 * In case all entries are ignored, the ERR queue will be empty afterwards.
 * For an empty ERR queue  0 is returned.
 *
 * `ignore_err` may be NULL, in which case this returns the HEAD values.
 *
 * `flags` is present for OpenSSL compatibility, but will always be
 * set to 0, since we do not keep flags at ERR entries.
 */
unsigned long wc_PeekErrorNodeLineData(const char **file, int *line,
                                       const char **data, int *flags,
                                       int (*ignore_err)(int err))
{
    WOLFSSL_ENTER("wc_PeekErrorNodeLineData");

    /* No data or flags stored - error display only in Nginx. */
    if (data != NULL) {
        *data = "";
    }
    if (flags != NULL) {
        *flags = 0;
    }

    while (1) {
        int ret = wc_PeekErrorNode(0, file, NULL, line);
        if (ret == WC_NO_ERR_TRACE(BAD_STATE_E)) {
            WOLFSSL_MSG("Issue peeking at error node in queue");
            return 0;
        }
        /* OpenSSL uses positive error codes */
        if (ret < 0) {
            ret = -ret;
        }
        /* an error that the caller wants to ignore? */
        if (ignore_err && ignore_err(ret)) {
          wc_RemoveErrorNode(0);
          continue;
        }

        return (unsigned long)ret;
    }
}

/**
 * Get the error value at the HEAD of the ERR queue or 0 if the queue
 * is empty. The HEAD entry is removed by this call.
 */
int wc_GetErrorNodeErr(void)
{
    int ret;

    WOLFSSL_ENTER("wc_GetErrorNodeErr");

    ret = wc_PullErrorNode(NULL, NULL, NULL);
    if (ret < 0) {
        if (ret == WC_NO_ERR_TRACE(BAD_STATE_E)) {
            ret = 0; /* no errors in queue */
        }
        else {
            WOLFSSL_MSG("Error with pulling error node!");
            WOLFSSL_LEAVE("wolfSSL_ERR_get_error", ret);
            ret = 0 - ret; /* return absolute value of error */
            /* panic and try to clear out nodes */
            wc_ClearErrorNodes();
        }
    }
    return ret;
}

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
/* This callback allows the application to provide a custom error printing
 * function. */
void wc_ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
                            void *u)
{
    size_t i;

    WOLFSSL_ENTER("wc_ERR_print_errors_cb");

    if (cb == NULL) {
        /* Invalid param */
        return;
    }

    for (i = 0; i < wc_errors.count; ++i) {
        struct wc_error_entry *entry = get_entry((int)i);
        if (entry == NULL)
            break;
        cb(entry->reason, XSTRLEN(entry->reason), u);
    }

    wc_ClearErrorNodes();
}
#endif /* !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) */

#else /* ERROR_QUEUE_PER_THREAD */
/* Error queue is a global list. This is the original implementation and
 * the fallback on platforms that do not have thread-local-storage.
 *
 * Access and manipulations of the list are protected by a mutex, however
 * that does not prevent errors from another thread showing up. Therefore,
 * its usefulness  is limited to applications with restricted thread
 * concurrency in using wolfSSL.
 */
#ifndef ERROR_QUEUE_MAX
/* With a global list, we allow a higher limit. */
#define ERROR_QUEUE_MAX 100
#endif

/* The information we keep about a single error */
struct wc_error_queue {
    void*  heap; /* the heap hint used with nodes creation */
    struct wc_error_queue* next;
    struct wc_error_queue* prev;
    char   error[WOLFSSL_MAX_ERROR_SZ];
    char   file[WOLFSSL_MAX_ERROR_SZ];
    int    value;
    int    line;
};

/* The global list of errors encountered */
static struct wc_error_queue* wc_errors;
static int wc_errors_count = 0;
/* pointer to last node in queue to make insertion O(1) */
static struct wc_error_queue* wc_last_node;
/* The 'current' cursor the application is using to access the list */
static struct wc_error_queue* wc_current_node;

/* heap info currently used for allocation of entries */
static void* wc_error_heap;

/* mutex for list operation protection */
static wolfSSL_Mutex wc_error_mutex WOLFSSL_MUTEX_INITIALIZER_CLAUSE(wc_error_mutex);
#define ERRQ_MUTEX_INIT()      wc_InitMutex(&wc_error_mutex)
#define ERRQ_MUTEX_FREE()      wc_FreeMutex(&wc_error_mutex)
#define ERRQ_LOCK()            wc_LockMutex(&wc_error_mutex)
#define ERRQ_UNLOCK()          wc_UnLockMutex(&wc_error_mutex)

/* Internal function that is called by wolfCrypt_Init() */
int wc_LoggingInit(void)
{
#ifndef WOLFSSL_MUTEX_INITIALIZER
    if (ERRQ_MUTEX_INIT() != 0) {
        WOLFSSL_MSG("Bad Init Mutex");
        return BAD_MUTEX_E;
    }
#endif
    wc_errors_count = 0;
    wc_errors          = NULL;
    wc_current_node    = NULL;
    wc_last_node       = NULL;
    return 0;
}


/* internal function that is called by wolfCrypt_Cleanup */
int wc_LoggingCleanup(void)
{
    /* clear logging entries */
    wc_ClearErrorNodes();
    /* free mutex */
#ifndef WOLFSSL_MUTEX_INITIALIZER
    if (ERRQ_MUTEX_FREE() != 0) {
        WOLFSSL_MSG("Bad Mutex free");
        return BAD_MUTEX_E;
    }
#endif
    return 0;
}

static int peekErrorNode(int idx, const char **file, const char **reason,
        int *line)
{
    struct wc_error_queue* err;

    if (idx < 0) {
        err = wc_last_node;
    }
    else {
        int i;

        err = (struct wc_error_queue*)wc_errors;
        for (i = 0; i < idx; i++) {
            if (err == NULL) {
                WOLFSSL_MSG("Error node not found. Bad index?");
                return BAD_FUNC_ARG;
            }
            err = err->next;
        }
    }

    if (err == NULL) {
        WOLFSSL_MSG("No Errors in queue");
        return BAD_STATE_E;
    }

    if (file != NULL) {
        *file = err->file;
    }
    if (reason != NULL) {
        *reason = err->error;
    }
    if (line != NULL) {
        *line = err->line;
    }

    return err->value;
}

/* peek at an error node
 *
 * idx : if -1 then the most recent node is looked at,
 *       otherwise search through queue for node at the given index starting
 *          from the absolute head wc_errors
 * file  : pointer to internal file string
 * reason : pointer to internal error reason
 * line  : line number that error happened at
 *
 * Returns a negative value in error case, on success returns the nodes error
 * value which is positive (absolute value)
 */
int wc_PeekErrorNode(int idx, const char **file, const char **reason,
        int *line)
{
    int ret;

    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return BAD_MUTEX_E;
    }
    ret = peekErrorNode(idx, file, reason, line);
    ERRQ_UNLOCK();
    return ret;
}

static int pullErrorNode(const char **file, const char **reason, int *line)
{
    struct wc_error_queue* err;
    int value;

    err = wc_current_node;
    if (err == NULL) {
        WOLFSSL_MSG("No Errors in queue");
        return BAD_STATE_E;
    }

    if (file != NULL) {
        *file = err->file;
    }
    if (reason != NULL) {
        *reason = err->error;
    }
    if (line != NULL) {
        *line = err->line;
    }
    value = err->value;
    wc_current_node = err->next;

    return value;
}

/* Pulls the current node from error queue and increments current state.
 * Note: this does not delete nodes because input arguments are pointing to
 *       node buffers.
 *
 * file   pointer to file that error was in. Can be NULL to return no file.
 * reason error string giving reason for error. Can be NULL to return no reason.
 * line   return line number of where error happened.
 *
 * returns the error value on success and BAD_MUTEX_E or BAD_STATE_E on failure
 */
int wc_PullErrorNode(const char **file, const char **reason, int *line)
{
    int value;

    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return BAD_MUTEX_E;
    }

    value = pullErrorNode(file, reason, line);

    ERRQ_UNLOCK();
    return value;
}

/* create new error node and add it to the queue
 * buffers are assumed to be of size WOLFSSL_MAX_ERROR_SZ for this internal
 * function. */
int wc_AddErrorNode(int error, int line, char* buf, char* file)
{
    struct wc_error_queue* err;

    if (wc_errors_count >= ERROR_QUEUE_MAX) {
        WOLFSSL_MSG("Error queue is full, at ERROR_QUEUE_MAX");
        return MEMORY_E;
    }

    err = (struct wc_error_queue*)XMALLOC(
            sizeof(struct wc_error_queue), wc_error_heap, DYNAMIC_TYPE_LOG);
    if (err == NULL) {
        WOLFSSL_MSG("Unable to create error node for log");
        return MEMORY_E;
    }
    else {
        int sz;

        XMEMSET(err, 0, sizeof(struct wc_error_queue));
        err->heap = wc_error_heap;
        sz = (int)XSTRLEN(buf);
        if (sz > WOLFSSL_MAX_ERROR_SZ - 1) {
            sz = WOLFSSL_MAX_ERROR_SZ - 1;
        }
        if (sz > 0) {
            XMEMCPY(err->error, buf, (size_t)sz);
        }

        sz = (int)XSTRLEN(file);
        if (sz > WOLFSSL_MAX_ERROR_SZ - 1) {
            sz = WOLFSSL_MAX_ERROR_SZ - 1;
        }
        if (sz > 0) {
            XMEMCPY(err->file, file, (size_t)sz);
        }

        err->value = error;
        err->line  = line;

        /* make sure is terminated */
        err->error[WOLFSSL_MAX_ERROR_SZ - 1] = '\0';
        err->file[WOLFSSL_MAX_ERROR_SZ - 1]  = '\0';


        /* since is queue place new node at last of the list */
        if (wc_last_node == NULL) {
            /* case of first node added to queue */
            if (wc_errors != NULL) {
                /* check for unexpected case before over writing wc_errors */
                WOLFSSL_MSG("ERROR in adding new node to logging queue!!");
                /* In the event both wc_last_node and wc_errors are NULL, err
                 * goes unassigned to external wc_errors, wc_last_node. Free
                 * err in this instance since wc_ClearErrorNodes will not
                 */
                XFREE(err, wc_error_heap, DYNAMIC_TYPE_LOG);
            }
            else {
                wc_errors    = err;
                wc_last_node = err;
                wc_current_node = err;
            }
        }
        else {
            wc_last_node->next = err;
            err->prev = wc_last_node;
            wc_last_node = err;

            /* check the case where have read to the end of the queue and the
             * current node to read needs updated */
            if (wc_current_node == NULL) {
                wc_current_node = err;
            }
        }
        wc_errors_count++;
    }
    return 0;
}

/* returns the current index into the queue, which is the node that
 * wc_current_node is pointing to. It can be greater than zero in cases
 * where wc_PullErrorNode() has been called without the node having been
 * removed. */
static int getErrorNodeCurrentIdx(void)
{
    int ret = 0;
    struct wc_error_queue* current;

    current = (struct wc_error_queue*)wc_errors;
    while (current != wc_current_node && current != NULL) {
        current = current->next;
        ret++;
    }

    /* wc_current_node was not found in the list! use index 0 */
    if (current == NULL) {
        ret = 0;
    }
    return ret;
}

static void removeErrorNode(int idx)
{
    struct wc_error_queue* current;

    if (idx == -1) {
        current = wc_last_node;
    }
    else {
        current = (struct wc_error_queue*)wc_errors;
        for (; current != NULL && idx > 0; idx--)
             current = current->next;
    }
    if (current != NULL) {
        if (current->prev != NULL)
            current->prev->next = current->next;
        if (current->next != NULL)
            current->next->prev = current->prev;
        if (wc_last_node == current)
            wc_last_node = current->prev;
        if (wc_errors == current)
            wc_errors = current->next;
        if (wc_current_node == current)
            wc_current_node = current->next;
        XFREE(current, current->heap, DYNAMIC_TYPE_LOG);
        wc_errors_count--;

        /* last node left in list was free'd, reset list head */
        if (wc_errors_count == 0) {
            wc_errors       = NULL;
            wc_last_node    = NULL;
            wc_current_node = NULL;
        }
    }
}

/* Removes the error node at the specified index.
 * idx : if -1 then the most recent node is looked at,
 *       otherwise search through queue for node at the given index starting
 *          from the absolute head wc_errors
 */
void wc_RemoveErrorNode(int idx)
{
    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return;
    }

    removeErrorNode(idx);

    ERRQ_UNLOCK();
}

static void clearErrorNodes(void)
{
    struct wc_error_queue* current;
    struct wc_error_queue* next;
    /* free all nodes from error queue (even previously 'pulled' ones) starting
     * at the lists absolute head of wc_errors */

    current = (struct wc_error_queue*)wc_errors;
    while (current != NULL) {
        next = current->next;
        XFREE(current, current->heap, DYNAMIC_TYPE_LOG);
        current = next;
    }

    wc_errors_count = 0;
    wc_errors       = NULL;
    wc_last_node    = NULL;
    wc_current_node = NULL;
}

/* Clears out the list of error nodes.
 */
void wc_ClearErrorNodes(void)
{
    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return;
    }

    clearErrorNodes();

    ERRQ_UNLOCK();
}

int wc_SetLoggingHeap(void* h)
{
    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return BAD_MUTEX_E;
    }
    wc_error_heap = h;
    ERRQ_UNLOCK();
    return 0;
}

/* frees all nodes in the queue
 *
 * id  this is the thread id
 */
int wc_ERR_remove_state(void)
{
    struct wc_error_queue* current;
    struct wc_error_queue* next;

    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return BAD_MUTEX_E;
    }

    /* free all nodes from error queue */
    current = (struct wc_error_queue*)wc_errors;
    while (current != NULL) {
        next = current->next;
        XFREE(current, current->heap, DYNAMIC_TYPE_LOG);
        current = next;
    }

    wc_errors_count = 0;
    wc_errors          = NULL;
    wc_last_node       = NULL;

    ERRQ_UNLOCK();

    return 0;
}

unsigned long wc_PeekErrorNodeLineData(const char **file, int *line,
                                       const char **data, int *flags,
                                       int (*ignore_err)(int err))
{
    int idx;

    WOLFSSL_ENTER("wc_PeekErrorNodeLineData");

/* No data or flags stored - error display only in Nginx. */
    if (data != NULL) {
        *data = "";
    }
    if (flags != NULL) {
        *flags = 0;
    }

    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return (unsigned long)(0 - BAD_MUTEX_E);
    }

    idx = getErrorNodeCurrentIdx();
    while (1) {
        int ret = peekErrorNode(idx, file, NULL, line);
        if (ret == WC_NO_ERR_TRACE(BAD_MUTEX_E) ||
            ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG) ||
            ret == WC_NO_ERR_TRACE(BAD_STATE_E)) {
            ERRQ_UNLOCK();
            WOLFSSL_MSG("Issue peeking at error node in queue");
            return 0;
        }
        /* OpenSSL uses positive error codes */
        if (ret < 0) {
            ret = -ret;
        }

        if (ignore_err && ignore_err(ret)) {
          removeErrorNode(idx);
          continue;
        }

        ERRQ_UNLOCK();
        return (unsigned long)ret;
    }
}

int wc_GetErrorNodeErr(void)
{
    int ret;

    WOLFSSL_ENTER("wc_GetErrorNodeErr");

    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
        return (0 - BAD_MUTEX_E);
    }

    ret = pullErrorNode(NULL, NULL, NULL);
    if (ret < 0) {
        if (ret == WC_NO_ERR_TRACE(BAD_STATE_E)) {
            ret = 0; /* no errors in queue */
        }
        else {
            WOLFSSL_MSG("Error with pulling error node!");
            WOLFSSL_LEAVE("wolfSSL_ERR_get_error", ret);
            ret = 0 - ret; /* return absolute value of error */
            /* panic and try to clear out nodes */
            clearErrorNodes();
        }
    }
    else {
        int idx = getErrorNodeCurrentIdx();
        if (idx < 0) {
            WOLFSSL_MSG("Error with getting current index!");
            ret = BAD_STATE_E;
            WOLFSSL_LEAVE("wolfSSL_ERR_get_error", ret);

            /* panic and try to clear out nodes and reset queue state */
            clearErrorNodes();
        }
        else if (idx > 0) {
            idx -= 1;
            removeErrorNode(idx);
        }
        else {
            /* if current idx is 0 then the queue only had one node */
            removeErrorNode(idx);
        }
    }

    ERRQ_UNLOCK();
    return ret;
}

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
/* This callback allows the application to provide a custom error printing
 * function. */
void wc_ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
                            void *u)
{
    WOLFSSL_ENTER("wc_ERR_print_errors_cb");

    if (cb == NULL) {
        /* Invalid param */
        return;
    }

    if (ERRQ_LOCK() != 0) {
        WOLFSSL_MSG("Lock debug mutex failed");
    }
    else {
        /* free all nodes from error queue and print them to file */
        struct wc_error_queue *current;
        struct wc_error_queue *next;

        current = (struct wc_error_queue *)wc_errors;
        while (current != NULL)
        {
            next = current->next;
            cb(current->error, XSTRLEN(current->error), u);
            XFREE(current, current->heap, DYNAMIC_TYPE_LOG);
            current = next;
        }

        /* set global pointers to match having been freed */
        wc_errors_count = 0;
        wc_errors = NULL;
        wc_last_node = NULL;

        ERRQ_UNLOCK();
    }
}
#endif /* !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) */

#endif /* !ERROR_QUEUE_PER_THREAD */

#else  /* WOLFSSL_HAVE_ERROR_QUEUE */
/* NO ERROR_QUEUE at all */

int wc_LoggingInit(void)
{
    return 0;
}


/* internal function that is called by wolfCrypt_Cleanup */
int wc_LoggingCleanup(void)
{
    return 0;
}

int wc_PeekErrorNode(int idx, const char **file, const char **reason,
        int *line)
{
    (void)idx;
    (void)file;
    (void)reason;
    (void)line;
    WOLFSSL_MSG("Error queue turned off, can not peak nodes");
    return NOT_COMPILED_IN;
}

int wc_PullErrorNode(const char **file, const char **reason, int *line)
{
    (void)file;
    (void)reason;
    (void)line;
    WOLFSSL_MSG("Error queue turned off, can not pull nodes");
    return NOT_COMPILED_IN;
}

int wc_AddErrorNode(int error, int line, char* buf, char* file)
{
    (void)error;
    (void)line;
    (void)buf;
    (void)file;
    WOLFSSL_MSG("Error queue turned off, can not add nodes");
    return NOT_COMPILED_IN;
}

void wc_RemoveErrorNode(int idx)
{
    (void)idx;
    WOLFSSL_MSG("Error queue turned off, can not remove nodes");
}

void wc_ClearErrorNodes(void)
{
    WOLFSSL_MSG("Error queue turned off, can not clear nodes");
}

int wc_SetLoggingHeap(void* h)
{
    (void)h;
    return 0;
}

int wc_ERR_remove_state(void)
{
    return 0;
}

/* Returns 0 both when the error queue is empty and when
 * WOLFSSL_HAVE_ERROR_QUEUE is not compiled in. */
unsigned long wc_PeekErrorNodeLineData(const char **file, int *line,
                                       const char **data, int *flags,
                                       int (*ignore_err)(int err))
{
    WOLFSSL_ENTER("wc_PeekErrorNodeLineData");

    (void)line;
    (void)file;
    (void)ignore_err;
    if (data != NULL) {
        *data = "";
    }
    if (flags != NULL) {
        *flags = 0;
    }
    return 0;
}

/* Returns 0 both when the error queue is empty and when
 * WOLFSSL_HAVE_ERROR_QUEUE is not compiled in. */
int wc_GetErrorNodeErr(void)
{
    WOLFSSL_ENTER("wc_GetErrorNodeErr");
    return 0;
}

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
void wc_ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
                            void *u)
{
    WOLFSSL_ENTER("wc_ERR_print_errors_cb");
    (void)cb;
    (void)u;
}
#endif /* !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) */

#endif /* !WOLFSSL_HAVE_ERROR_QUEUE */

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
/* empties out the error queue into the file */
static int wc_ERR_dump_to_file (const char *str, size_t len, void *u)
{
    XFILE fp = (XFILE ) u;
    if (fprintf(fp, "%-*.*s\n", (int)len, (int)len, str) < 0)
        return IO_FAILED_E;
    return 0;
}

void wc_ERR_print_errors_fp(XFILE fp)
{
    WOLFSSL_ENTER("wc_ERR_print_errors_fp");

    /* Send all errors to the wc_ERR_dump_to_file function */
    wc_ERR_print_errors_cb(wc_ERR_dump_to_file, fp);
}

#endif /* !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) */

#endif /* defined(OPENSSL_EXTRA) || defined(DEBUG_WOLFSSL_VERBOSE)
          || defined(HAVE_MEMCACHED) */

/*
 * When using OPENSSL_EXTRA or DEBUG_WOLFSSL_VERBOSE macro then WOLFSSL_ERROR is
 * mapped to new function WOLFSSL_ERROR_LINE which gets the line # and function
 * name where WOLFSSL_ERROR is called at.
 */
#if defined(DEBUG_WOLFSSL) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA)

#ifdef WOLFSSL_HAVE_ERROR_QUEUE
void WOLFSSL_ERROR_LINE(int error, const char* func, unsigned int line,
        const char* file, void* usrCtx)
#else
void WOLFSSL_ERROR(int error)
#endif
{
#ifdef WOLFSSL_ASYNC_CRYPT
    if (error != WC_NO_ERR_TRACE(WC_PENDING_E))
#endif
    {
        char buffer[WOLFSSL_MAX_ERROR_SZ];

    #ifdef WOLFSSL_HAVE_ERROR_QUEUE
        (void)usrCtx; /* a user ctx for future flexibility */
        (void)func;

        if (ERRQ_LOCK() != 0) {
            WOLFSSL_MSG("Lock debug mutex failed");
            (void)XSNPRINTF(buffer, sizeof(buffer),
                    "wolfSSL error occurred, error = %d", error);
        }
        else {
            int len;
            #if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
            /* If running in compatibility mode do not add want read and
               want right to error queue */
            if (error != WC_NO_ERR_TRACE(WANT_READ) &&
                error != WC_NO_ERR_TRACE(WANT_WRITE)) {
            #endif
            if (error < 0)
                error = error - (2 * error); /* get absolute value */
            /* XSNPRINTF ignores the size under WOLF_C89. */
            len = XSNPRINTF(buffer, sizeof(buffer),
                    "wolfSSL error occurred, error = %d line:%u file:",
                    error, line);
            if ((len > 0) && (len < (int)sizeof(buffer))) {
                (void)XSNPRINTF(buffer + len, sizeof(buffer) - (size_t)len,
                        "%.*s", (int)sizeof(buffer) - 1 - len, file);
            }

            if (wc_AddErrorNode(error, (int)line, buffer, (char*)file) != 0) {
                WOLFSSL_MSG("Error creating logging node");
                /* with void function there is no return here, continue on
                 * to unlock mutex and log what buffer was created. */
            }
            #if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
            }
            else {
                (void)XSNPRINTF(buffer, sizeof(buffer),
                    "wolfSSL error occurred, error = %d", error);
            }
            #endif

            ERRQ_UNLOCK();
        }
    #else
        (void)XSNPRINTF(buffer, sizeof(buffer),
                "wolfSSL error occurred, error = %d", error);
    #endif

    #ifdef DEBUG_WOLFSSL
        if (loggingEnabled)
            wolfssl_log(ERROR_LOG, NULL, 0, buffer);
    #endif
    }
}

void WOLFSSL_ERROR_MSG(const char* msg)
{
#ifdef DEBUG_WOLFSSL
    if (loggingEnabled)
        wolfssl_log(ERROR_LOG, NULL, 0, msg);
#else
    (void)msg;
#endif
}

#endif  /* DEBUG_WOLFSSL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

#if defined(WOLFSSL_DEBUG_TRACE_ERROR_CODES) || \
    defined(WOLFSSL_DEBUG_TRACE_ERROR_CODES_SUPPORT)

#ifndef WOLFSSL_DEBUG_TRACE_ERROR_CODES_INIT_STATE
    #define WOLFSSL_DEBUG_TRACE_ERROR_CODES_INIT_STATE 1
#endif

#ifdef WOLFSSL_ATOMIC_OPS
static wolfSSL_Atomic_Int wc_debug_trace_error_codes_state =
    WOLFSSL_ATOMIC_INITIALIZER(WOLFSSL_DEBUG_TRACE_ERROR_CODES_INIT_STATE);
#else
static int wc_debug_trace_error_codes_state =
    WOLFSSL_DEBUG_TRACE_ERROR_CODES_INIT_STATE;
#endif

int wc_debug_trace_error_codes_enabled(void) {
    return WOLFSSL_ATOMIC_LOAD(wc_debug_trace_error_codes_state);
}

int wc_debug_trace_error_codes_set(int state) {
    return wolfSSL_Atomic_Int_Exchange(&wc_debug_trace_error_codes_state,
                                       state);
}

#endif /* WOLFSSL_DEBUG_TRACE_ERROR_CODES ||      */
       /* WOLFSSL_DEBUG_TRACE_ERROR_CODES_SUPPORT */

#ifdef WOLFSSL_DEBUG_BACKTRACE_ERROR_CODES

#ifdef WOLFSSL_LINUXKM

int wc_backtrace_render(void) {
    dump_stack();
    return 0;
}

#else /* !WOLFSSL_LINUXKM */

#include <backtrace-supported.h>

#if BACKTRACE_SUPPORTED != 1
    #error WOLFSSL_DEBUG_BACKTRACE_ERROR_CODES is defined but BACKTRACE_SUPPORTED is 0.
#endif

#if !defined(WOLFSSL_MUTEX_INITIALIZER) && defined(WOLFSSL_NO_ATOMICS)
    #error WOLFSSL_DEBUG_BACKTRACE_ERROR_CODES requires WOLFSSL_MUTEX_INITIALIZER or wolfSSL_Atomic_Ints.
#endif

#include <backtrace.h>

#ifdef XFILE

static XFILE wolfssl_backtrace_file = XBADFILE;

XFILE wc_backtrace_set_fp(XFILE new_fp) {
    XFILE old_fp = wolfssl_backtrace_file;
    if (new_fp == NULL)
        wolfssl_backtrace_file = XBADFILE;
    else
        wolfssl_backtrace_file = new_fp;
    return old_fp;
}

#define WOLFSSL_BACKTRACE_PRINTF(...) (                             \
    (wolfssl_backtrace_file == XBADFILE) ?                          \
     WOLFSSL_DEBUG_PRINTF(__VA_ARGS__) :                            \
     WOLFSSL_DEBUG_PRINTF_FN(wolfssl_backtrace_file, __VA_ARGS__))

#else /* !XFILE */

/* libbacktrace doesn't support any targets with no XFILE, but keep it buildable
 * just in case.
 */
#define WOLFSSL_BACKTRACE_PRINTF(...) WOLFSSL_DEBUG_PRINTF(__VA_ARGS__)

#endif /* !XFILE */

static int backtrace_callback(void *data, uintptr_t pc, const char *filename,
                              int lineno, const char *function)
{
    if (function == NULL)
        return 0;
    /* the first callback is for the call to wc_print_backtrace() -- skip it. */
    if (*(int *)data == 0) {
        *(int *)data = 1;
        return 0;
    }
    WOLFSSL_BACKTRACE_PRINTF("    #%d %p in %s %s:%d\n", (*(int *)data)++,
                         (void *)pc, function, filename, lineno);
    return 0;
}

static void backtrace_error(void *data, const char *msg, int errnum) {
    (void)data;
    WOLFSSL_BACKTRACE_PRINTF("ERR TRACE: error %d while backtracing: %s",
                         errnum, msg);
}

static void backtrace_creation_error(void *data, const char *msg, int errnum) {
    (void)data;
    WOLFSSL_BACKTRACE_PRINTF("ERR TRACE: internal error %d "
            "while initializing backtrace facility: %s", errnum, msg);
}

static int backtrace_init(struct backtrace_state **backtrace_state) {
#ifdef WOLFSSL_MUTEX_INITIALIZER
    static wolfSSL_Mutex backtrace_create_state_mutex =
        WOLFSSL_MUTEX_INITIALIZER(backtrace_create_state_mutex);
    if (wc_LockMutex(&backtrace_create_state_mutex) != 0)
        return -1;
#elif defined(WOLFSSL_ATOMIC_OPS)
    static wolfSSL_Atomic_Int init_count = 0;
    if (wolfSSL_Atomic_Int_FetchAdd(&init_count, 1) != 1)
        return -1;
#endif
    if (*backtrace_state == NULL) {
        /* passing a NULL filename to backtrace_create_state() tells
         * libbacktrace to use a target-specific strategy to determine the
         * executable.  "libbacktrace supports ELF, PE/COFF, Mach-O, and XCOFF
         * executables with DWARF debugging information.  In other words, it
         * supports GNU/Linux, *BSD, macOS, Windows, and AIX."
         */
        *backtrace_state = backtrace_create_state(
            NULL, 0, backtrace_creation_error, NULL);
    }
#ifdef WOLFSSL_MUTEX_INITIALIZER
    wc_UnLockMutex(&backtrace_create_state_mutex);
#endif
    if (*backtrace_state == NULL)
        return -1;
    return 0;
}

int wc_backtrace_render(void) {
    static wolfSSL_Mutex backtrace_mutex
        WOLFSSL_MUTEX_INITIALIZER_CLAUSE(backtrace_mutex);
    static struct backtrace_state *backtrace_state = NULL;
    int depth = 0;
    int ret;

#ifndef WOLFSSL_MUTEX_INITIALIZER
    static wolfSSL_Atomic_Int init_count = 0;
    if (init_count != 1) {
        int cur_init_count = wolfSSL_Atomic_Int_FetchSub(&init_count, 1);
        if (cur_init_count != 0) {
            (void)wolfSSL_Atomic_Int_FetchAdd(&init_count, 1);
            return WC_NO_ERR_TRACE(DEADLOCK_AVERTED_E);
        }
        ret = wc_InitMutex(&backtrace_mutex);
        if (ret != 0)
            return ret;
        /* set init_count to 1, race-free: (-1) - (0-2) = 1 */
        (void)wolfSSL_Atomic_Int_FetchSub(&init_count, cur_init_count - 2);
    }
#endif

    /* backtrace_state can't be shared between threads even when
     * BACKTRACE_SUPPORTS_THREADS == 1, so we serialize the render op.  this
     * helpfully mutexes the initialization too.
     */
    ret = wc_LockMutex(&backtrace_mutex);
    if (ret != 0)
        return ret;

    if (backtrace_state == NULL) {
        if (backtrace_init(&backtrace_state) < 0) {
            wc_UnLockMutex(&backtrace_mutex);
            return WC_NO_ERR_TRACE(BAD_STATE_E);
        }
    }

    /* note that the optimizer can produce misleading backtraces, even with
     * -funwind-tables.  in contrast, the macro-generated "ERR TRACE" message
     * from WC_ERR_TRACE() always accurately identifies the error code point.
     */
    backtrace_full(backtrace_state, 0, backtrace_callback, backtrace_error,
                   (void *)&depth);

    wc_UnLockMutex(&backtrace_mutex);

    return 0;
}
#endif /* !WOLFSSL_LINUXKM */

#endif /* WOLFSSL_DEBUG_BACKTRACE_ERROR_CODES */
