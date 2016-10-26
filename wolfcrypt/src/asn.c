/* asn.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/*
ASN Options:
 * NO_ASN_TIME: Disables time parts of the ASN code for systems without an RTC
    or wishing to save space.
 * IGNORE_NAME_CONSTRAINTS: Skip ASN name checks.
*/

#ifndef NO_ASN

#ifdef HAVE_RTP_SYS
    #include "os.h"           /* dc_rtc_api needs    */
    #include "dc_rtc_api.h"   /* to get current time */
#endif

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/md2.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef NO_RC4
    #include <wolfssl/wolfcrypt/arc4.h>
#endif

#ifdef HAVE_NTRU
    #include "libntruencrypt/ntru_crypto.h"
#endif

#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#ifdef WOLFSSL_DEBUG_ENCODING
    #if defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
        #if MQX_USE_IO_OLD
            #include <fio.h>
        #else
            #include <nio.h>
        #endif
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of XSTRNCPY */
    #pragma warning(disable: 4996)
#endif


#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

#ifndef NO_ASN_TIME
#if defined(HAVE_RTP_SYS)
    /* uses parital <time.h> structures */
    #define XTIME(tl)       (0)
    #define XGMTIME(c, t)   rtpsys_gmtime((c))

#elif defined(MICRIUM)
    #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
        #define XVALIDATE_DATE(d, f, t) NetSecure_ValidateDateHandler((d), (f), (t))
    #else
        #define XVALIDATE_DATE(d, f, t) (0)
    #endif
    #define NO_TIME_H
    /* since Micrium not defining XTIME or XGMTIME, CERT_GEN not available */

#elif defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)
    #include <time.h>
    #define XTIME(t1)       pic32_time((t1))
    #define XGMTIME(c, t)   gmtime((c))

#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #define XTIME(t1)       mqx_time((t1))
    #define HAVE_GMTIME_R

#elif defined(FREESCALE_KSDK_BM) || defined(FREESCALE_FREE_RTOS)
    #include <time.h>
    #define XTIME(t1)       ksdk_time((t1))
    #define XGMTIME(c, t)   gmtime((c))

#elif defined(USER_TIME)
    /* user time, and gmtime compatible functions, there is a gmtime
       implementation here that WINCE uses, so really just need some ticks
       since the EPOCH
    */
    #define WOLFSSL_GMTIME
    #define USE_WOLF_TM
    #define USE_WOLF_TIME_T

#elif defined(TIME_OVERRIDES)
    /* user would like to override time() and gmtime() functionality */
    #ifndef HAVE_TIME_T_TYPE
        #define USE_WOLF_TIME_T
    #endif
    #ifndef HAVE_TM_TYPE
        #define USE_WOLF_TM
    #endif
    #define NEED_TMP_TIME

#elif defined(IDIRECT_DEV_TIME)
    /*Gets the timestamp from cloak software owned by VT iDirect
    in place of time() from <time.h> */
    #include <time.h>
    #define XTIME(t1)       idirect_time((t1))
    #define XGMTIME(c, t)   gmtime((c))

#elif defined(_WIN32_WCE)
    #include <windows.h>
    #define XTIME(t1)       windows_time((t1))
    #define WOLFSSL_GMTIME

#else
    /* default */
    /* uses complete <time.h> facility */
    #include <time.h>
#endif


/* Map default time functions */
#if !defined(XTIME) && !defined(TIME_OVERRIDES) && !defined(USER_TIME)
    #define XTIME(tl)       time((tl))
#endif
#if !defined(XGMTIME) && !defined(TIME_OVERRIDES)
    #if defined(WOLFSSL_GMTIME) || !defined(HAVE_GMTIME_R)
        #define XGMTIME(c, t)   gmtime((c))
    #else
        #define XGMTIME(c, t)   gmtime_r((c), (t))
        #define NEED_TMP_TIME
    #endif
#endif
#if !defined(XVALIDATE_DATE) && !defined(HAVE_VALIDATE_DATE)
    #define USE_WOLF_VALIDDATE
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#endif

/* wolf struct tm and time_t */
#if defined(USE_WOLF_TM)
    struct tm {
        int  tm_sec;     /* seconds after the minute [0-60] */
        int  tm_min;     /* minutes after the hour [0-59] */
        int  tm_hour;    /* hours since midnight [0-23] */
        int  tm_mday;    /* day of the month [1-31] */
        int  tm_mon;     /* months since January [0-11] */
        int  tm_year;    /* years since 1900 */
        int  tm_wday;    /* days since Sunday [0-6] */
        int  tm_yday;    /* days since January 1 [0-365] */
        int  tm_isdst;   /* Daylight Savings Time flag */
        long tm_gmtoff;  /* offset from CUT in seconds */
        char *tm_zone;   /* timezone abbreviation */
    };
#endif /* USE_WOLF_TM */
#if defined(USE_WOLF_TIME_T)
    typedef long time_t;
#endif

/* forward declarations */
#if defined(USER_TIME)
    struct tm* gmtime(const time_t* timer);
    extern time_t XTIME(time_t * timer);

    #ifdef STACK_TRAP
        /* for stack trap tracking, don't call os gmtime on OS X/linux,
           uses a lot of stack spce */
        extern time_t time(time_t * timer);
        #define XTIME(tl)  time((tl))
    #endif /* STACK_TRAP */

#elif defined(TIME_OVERRIDES)
    extern time_t XTIME(time_t * timer);
    extern struct tm* XGMTIME(const time_t* timer, struct tm* tmp);
#endif


#if defined(_WIN32_WCE)
time_t windows_time(time_t* timer)
{
    SYSTEMTIME     sysTime;
    FILETIME       fTime;
    ULARGE_INTEGER intTime;
    time_t         localTime;

    if (timer == NULL)
        timer = &localTime;

    GetSystemTime(&sysTime);
    SystemTimeToFileTime(&sysTime, &fTime);

    XMEMCPY(&intTime, &fTime, sizeof(FILETIME));
    /* subtract EPOCH */
    intTime.QuadPart -= 0x19db1ded53e8000;
    /* to secs */
    intTime.QuadPart /= 10000000;
    *timer = (time_t)intTime.QuadPart;

    return *timer;
}
#endif /*  _WIN32_WCE */

#if defined(WOLFSSL_GMTIME)
struct tm* gmtime(const time_t* timer)
{
    #define YEAR0          1900
    #define EPOCH_YEAR     1970
    #define SECS_DAY       (24L * 60L * 60L)
    #define LEAPYEAR(year) (!((year) % 4) && (((year) % 100) || !((year) %400)))
    #define YEARSIZE(year) (LEAPYEAR(year) ? 366 : 365)

    static const int _ytab[2][12] =
    {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };

    static struct tm st_time;
    struct tm* ret = &st_time;
    time_t secs = *timer;
    unsigned long dayclock, dayno;
    int year = EPOCH_YEAR;

    dayclock = (unsigned long)secs % SECS_DAY;
    dayno    = (unsigned long)secs / SECS_DAY;

    ret->tm_sec  = (int) dayclock % 60;
    ret->tm_min  = (int)(dayclock % 3600) / 60;
    ret->tm_hour = (int) dayclock / 3600;
    ret->tm_wday = (int) (dayno + 4) % 7;        /* day 0 a Thursday */

    while(dayno >= (unsigned long)YEARSIZE(year)) {
        dayno -= YEARSIZE(year);
        year++;
    }

    ret->tm_year = year - YEAR0;
    ret->tm_yday = (int)dayno;
    ret->tm_mon  = 0;

    while(dayno >= (unsigned long)_ytab[LEAPYEAR(year)][ret->tm_mon]) {
        dayno -= _ytab[LEAPYEAR(year)][ret->tm_mon];
        ret->tm_mon++;
    }

    ret->tm_mday  = (int)++dayno;
    ret->tm_isdst = 0;

    return ret;
}
#endif /* WOLFSSL_GMTIME */


#if defined(HAVE_RTP_SYS)
#define YEAR0          1900

struct tm* rtpsys_gmtime(const time_t* timer)       /* has a gmtime() but hangs */
{
    static struct tm st_time;
    struct tm* ret = &st_time;

    DC_RTC_CALENDAR cal;
    dc_rtc_time_get(&cal, TRUE);

    ret->tm_year  = cal.year - YEAR0;       /* gm starts at 1900 */
    ret->tm_mon   = cal.month - 1;          /* gm starts at 0 */
    ret->tm_mday  = cal.day;
    ret->tm_hour  = cal.hour;
    ret->tm_min   = cal.minute;
    ret->tm_sec   = cal.second;

    return ret;
}

#endif /* HAVE_RTP_SYS */


#if defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)

/*
 * time() is just a stub in Microchip libraries. We need our own
 * implementation. Use SNTP client to get seconds since epoch.
 */
time_t pic32_time(time_t* timer)
{
#ifdef MICROCHIP_TCPIP_V5
    DWORD sec = 0;
#else
    uint32_t sec = 0;
#endif
    time_t localTime;

    if (timer == NULL)
        timer = &localTime;

#ifdef MICROCHIP_MPLAB_HARMONY
    sec = TCPIP_SNTP_UTCSecondsGet();
#else
    sec = SNTPGetUTCSeconds();
#endif
    *timer = (time_t) sec;

    return *timer;
}

#endif /* MICROCHIP_TCPIP */


#if defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)

time_t mqx_time(time_t* timer)
{
    time_t localTime;
    TIME_STRUCT time_s;

    if (timer == NULL)
        timer = &localTime;

    _time_get(&time_s);
    *timer = (time_t) time_s.SECONDS;

    return *timer;
}

#endif /* FREESCALE_MQX */

#if defined(FREESCALE_KSDK_BM) || defined(FREESCALE_FREE_RTOS)

#include "fsl_pit_driver.h"

time_t ksdk_time(time_t* timer)
{
    time_t localTime;

    if (timer == NULL)
        timer = &localTime;

    *timer = (PIT_DRV_ReadTimerUs(PIT_INSTANCE, PIT_CHANNEL)) / 1000000;
    return *timer;
}

#endif /* FREESCALE_KSDK_BM */

#if defined(WOLFSSL_TIRTOS)

time_t XTIME(time_t * timer)
{
    time_t sec = 0;

    sec = (time_t) Seconds_get();

    if (timer != NULL)
        *timer = sec;

    return sec;
}

#endif /* WOLFSSL_TIRTOS */


static INLINE word32 btoi(byte b)
{
    return b - 0x30;
}


/* two byte date/time, add to value */
static INLINE void GetTime(int* value, const byte* date, int* idx)
{
    int i = *idx;

    *value += btoi(date[i++]) * 10;
    *value += btoi(date[i++]);

    *idx = i;
}


#if defined(MICRIUM)

CPU_INT32S NetSecure_ValidateDateHandler(CPU_INT08U *date, CPU_INT08U format,
                                         CPU_INT08U dateType)
{
    CPU_BOOLEAN  rtn_code;
    CPU_INT32S   i;
    CPU_INT32S   val;
    CPU_INT16U   year;
    CPU_INT08U   month;
    CPU_INT16U   day;
    CPU_INT08U   hour;
    CPU_INT08U   min;
    CPU_INT08U   sec;

    i    = 0;
    year = 0u;

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            year = 1900;
        else
            year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        year += btoi(date[i++]) * 1000;
        year += btoi(date[i++]) * 100;
    }

    val = year;
    GetTime(&val, date, &i);
    year = (CPU_INT16U)val;

    val = 0;
    GetTime(&val, date, &i);
    month = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);
    day = (CPU_INT16U)val;

    val = 0;
    GetTime(&val, date, &i);
    hour = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);
    min = (CPU_INT08U)val;

    val = 0;
    GetTime(&val, date, &i);
    sec = (CPU_INT08U)val;

    return NetSecure_ValidateDate(year, month, day, hour, min, sec, dateType);
}

#endif /* MICRIUM */

#if defined(IDIRECT_DEV_TIME)

extern time_t getTimestamp();

time_t idirect_time(time_t * timer)
{
    time_t sec = getTimestamp();

    if (timer != NULL)
        *timer = sec;

    return sec;
}

#endif /* IDIRECT_DEV_TIME */

#endif /* !NO_ASN_TIME */

WOLFSSL_LOCAL int GetLength(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    int     length = 0;
    word32  i = *inOutIdx;
    byte    b;

    *len = 0;    /* default length */

    if ( (i+1) > maxIdx) {   /* for first read */
        WOLFSSL_MSG("GetLength bad index on input");
        return BUFFER_E;
    }

    b = input[i++];
    if (b >= ASN_LONG_LENGTH) {
        word32 bytes = b & 0x7F;

        if ( (i+bytes) > maxIdx) {   /* for reading bytes */
            WOLFSSL_MSG("GetLength bad long length");
            return BUFFER_E;
        }

        while (bytes--) {
            b = input[i++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    if ( (i+length) > maxIdx) {   /* for user of length */
        WOLFSSL_MSG("GetLength value exceeds buffer length");
        return BUFFER_E;
    }

    *inOutIdx = i;
    if (length > 0)
        *len = length;

    return length;
}


WOLFSSL_LOCAL int GetSequence(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


WOLFSSL_LOCAL int GetSet(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SET | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


/* Windows header clash for WinCE using GetVersion */
WOLFSSL_LOCAL int GetMyVersion(const byte* input, word32* inOutIdx,
                               int* version)
{
    word32 idx = *inOutIdx;

    WOLFSSL_ENTER("GetMyVersion");

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    if (input[idx++] != 0x01)
        return ASN_VERSION_E;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
}


#ifndef NO_PWDBASED
/* Get small count integer, 32 bits or less */
static int GetShortInt(const byte* input, word32* inOutIdx, int* number)
{
    word32 idx = *inOutIdx;
    word32 len;

    *number = 0;

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    len = input[idx++];
    if (len > 4)
        return ASN_PARSE_E;

    while (len--) {
        *number  = *number << 8 | input[idx++];
    }

    *inOutIdx = idx;

    return *number;
}
#endif /* !NO_PWDBASED */

#ifndef NO_ASN_TIME
/* May not have one, not an error */
static int GetExplicitVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

    WOLFSSL_ENTER("GetExplicitVersion");
    if (input[idx++] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

    /* go back as is */
    *version = 0;

    return 0;
}
#endif /* !NO_ASN_TIME */

int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx,
                  word32 maxIdx)
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    if (mp_init(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(mpi, (byte*)input + i, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

    *inOutIdx = i + length;
    return 0;
}

#if !defined(NO_RSA) && !defined(HAVE_USER_RSA)
static int GetIntRsa(RsaKey* key, mp_int* mpi, const byte* input,
                        word32* inOutIdx, word32 maxIdx)
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    (void)key;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > 0) {
        /* remove leading zero */
        if ( (b = input[i++]) == 0x00)
            length--;
        else
            i--;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_CAVIUM)
    if (key->asyncDev.marker == WOLFSSL_ASYNC_MARKER_RSA) {
        XMEMSET(mpi, 0, sizeof(mp_int));
        mpi->used = length;
    #ifdef USE_FAST_MATH
        if (length > (FP_SIZE * (int)sizeof(fp_digit))) {
            return MEMORY_E;
        }
        mpi->dpraw = (byte*)mpi->dp;
    #else
        mpi->dpraw = (byte*)XMALLOC(length, key->heap, DYNAMIC_TYPE_ASYNC_RSA);
    #endif
        if (mpi->dpraw == NULL) {
            return MEMORY_E;
        }

        XMEMCPY(mpi->dpraw, input + i, length);
    }
    else
#endif /* WOLFSSL_ASYNC_CRYPT && HAVE_CAVIUM */
    {
        if (mp_init(mpi) != MP_OKAY)
            return MP_INIT_E;

        if (mp_read_unsigned_bin(mpi, (byte*)input + i, length) != 0) {
            mp_clear(mpi);
            return ASN_GETINT_E;
        }
    }

    *inOutIdx = i + length;
    return 0;
}
#endif /* !NO_RSA && !HAVE_USER_RSA */


/* hashType */
static const byte hashMd2hOid[] = {42, 134, 72, 134, 247, 13, 2, 2};
static const byte hashMd5hOid[] = {42, 134, 72, 134, 247, 13, 2, 5};
static const byte hashSha1hOid[] = {43, 14, 3, 2, 26};
static const byte hashSha256hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 1};
static const byte hashSha384hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 2};
static const byte hashSha512hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 3};

/* sigType */
#ifndef NO_DSA
    static const byte sigSha1wDsaOid[] = {42, 134, 72, 206, 56, 4, 3};
#endif /* NO_DSA */
#ifndef NO_RSA
    static const byte sigMd2wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 2};
    static const byte sigMd5wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 4};
    static const byte sigSha1wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 5};
    static const byte sigSha256wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,11};
    static const byte sigSha384wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,12};
    static const byte sigSha512wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,13};
#endif /* NO_RSA */
#ifdef HAVE_ECC
    static const byte sigSha1wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 1};
    static const byte sigSha256wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 2};
    static const byte sigSha384wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 3};
    static const byte sigSha512wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 4};
#endif /* HAVE_ECC */

/* keyType */
#ifndef NO_DSA
    static const byte keyDsaOid[] = {42, 134, 72, 206, 56, 4, 1};
#endif /* NO_DSA */
#ifndef NO_RSA
    static const byte keyRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 1};
#endif /* NO_RSA */
#ifdef HAVE_NTRU
    static const byte keyNtruOid[] = {43, 6, 1, 4, 1, 193, 22, 1, 1, 1, 1};
#endif /* HAVE_NTRU */
#ifdef HAVE_ECC
    static const byte keyEcdsaOid[] = {42, 134, 72, 206, 61, 2, 1};
#endif /* HAVE_ECC */

/* curveType */
#ifdef HAVE_ECC
    /* See "ecc_sets" table in ecc.c */
#endif /* HAVE_ECC */

/* blkType */
static const byte blkDesCbcOid[]  = {43, 14, 3, 2, 7};
static const byte blkDes3CbcOid[] = {42, 134, 72, 134, 247, 13, 3, 7};

/* ocspType */
#ifdef HAVE_OCSP
    static const byte ocspBasicOid[] = {43, 6, 1, 5, 5, 7, 48, 1, 1};
    static const byte ocspNonceOid[] = {43, 6, 1, 5, 5, 7, 48, 1, 2};
#endif /* HAVE_OCSP */

/* certExtType */
static const byte extBasicCaOid[] = {85, 29, 19};
static const byte extAltNamesOid[] = {85, 29, 17};
static const byte extCrlDistOid[] = {85, 29, 31};
static const byte extAuthInfoOid[] = {43, 6, 1, 5, 5, 7, 1, 1};
static const byte extAuthKeyOid[] = {85, 29, 35};
static const byte extSubjKeyOid[] = {85, 29, 14};
static const byte extCertPolicyOid[] = {85, 29, 32};
static const byte extKeyUsageOid[] = {85, 29, 15};
static const byte extInhibitAnyOid[] = {85, 29, 54};
static const byte extExtKeyUsageOid[] = {85, 29, 37};
static const byte extNameConsOid[] = {85, 29, 30};

/* certAuthInfoType */
static const byte extAuthInfoOcspOid[] = {43, 6, 1, 5, 5, 7, 48, 1};
static const byte extAuthInfoCaIssuerOid[] = {43, 6, 1, 5, 5, 7, 48, 2};

/* certPolicyType */
static const byte extCertPolicyAnyOid[] = {85, 29, 32, 0};

/* certKeyUseType */
static const byte extAltNamesHwNameOid[] = {43, 6, 1, 5, 5, 7, 8, 4};

/* certKeyUseType */
static const byte extExtKeyUsageAnyOid[] = {85, 29, 37, 0};
static const byte extExtKeyUsageServerAuthOid[] = {43, 6, 1, 5, 5, 7, 3, 1};
static const byte extExtKeyUsageClientAuthOid[] = {43, 6, 1, 5, 5, 7, 3, 2};
static const byte extExtKeyUsageOcspSignOid[] = {43, 6, 1, 5, 5, 7, 3, 9};

/* kdfType */
static const byte pbkdf2Oid[] = {42, 134, 72, 134, 247, 13, 1, 5, 12};

static const byte* OidFromId(word32 id, word32 type, word32* oidSz)
{
    const byte* oid = NULL;

    *oidSz = 0;

    switch (type) {

        case oidHashType:
            switch (id) {
                case MD2h:
                    oid = hashMd2hOid;
                    *oidSz = sizeof(hashMd2hOid);
                    break;
                case MD5h:
                    oid = hashMd5hOid;
                    *oidSz = sizeof(hashMd5hOid);
                    break;
                case SHAh:
                    oid = hashSha1hOid;
                    *oidSz = sizeof(hashSha1hOid);
                    break;
                case SHA256h:
                    oid = hashSha256hOid;
                    *oidSz = sizeof(hashSha256hOid);
                    break;
                case SHA384h:
                    oid = hashSha384hOid;
                    *oidSz = sizeof(hashSha384hOid);
                    break;
                case SHA512h:
                    oid = hashSha512hOid;
                    *oidSz = sizeof(hashSha512hOid);
                    break;
            }
            break;

        case oidSigType:
            switch (id) {
                #ifndef NO_DSA
                case CTC_SHAwDSA:
                    oid = sigSha1wDsaOid;
                    *oidSz = sizeof(sigSha1wDsaOid);
                    break;
                #endif /* NO_DSA */
                #ifndef NO_RSA
                case CTC_MD2wRSA:
                    oid = sigMd2wRsaOid;
                    *oidSz = sizeof(sigMd2wRsaOid);
                    break;
                case CTC_MD5wRSA:
                    oid = sigMd5wRsaOid;
                    *oidSz = sizeof(sigMd5wRsaOid);
                    break;
                case CTC_SHAwRSA:
                    oid = sigSha1wRsaOid;
                    *oidSz = sizeof(sigSha1wRsaOid);
                    break;
                case CTC_SHA256wRSA:
                    oid = sigSha256wRsaOid;
                    *oidSz = sizeof(sigSha256wRsaOid);
                    break;
                case CTC_SHA384wRSA:
                    oid = sigSha384wRsaOid;
                    *oidSz = sizeof(sigSha384wRsaOid);
                    break;
                case CTC_SHA512wRSA:
                    oid = sigSha512wRsaOid;
                    *oidSz = sizeof(sigSha512wRsaOid);
                    break;
                #endif /* NO_RSA */
                #ifdef HAVE_ECC
                case CTC_SHAwECDSA:
                    oid = sigSha1wEcdsaOid;
                    *oidSz = sizeof(sigSha1wEcdsaOid);
                    break;
                case CTC_SHA256wECDSA:
                    oid = sigSha256wEcdsaOid;
                    *oidSz = sizeof(sigSha256wEcdsaOid);
                    break;
                case CTC_SHA384wECDSA:
                    oid = sigSha384wEcdsaOid;
                    *oidSz = sizeof(sigSha384wEcdsaOid);
                    break;
                case CTC_SHA512wECDSA:
                    oid = sigSha512wEcdsaOid;
                    *oidSz = sizeof(sigSha512wEcdsaOid);
                    break;
                #endif /* HAVE_ECC */
                default:
                    break;
            }
            break;

        case oidKeyType:
            switch (id) {
                #ifndef NO_DSA
                case DSAk:
                    oid = keyDsaOid;
                    *oidSz = sizeof(keyDsaOid);
                    break;
                #endif /* NO_DSA */
                #ifndef NO_RSA
                case RSAk:
                    oid = keyRsaOid;
                    *oidSz = sizeof(keyRsaOid);
                    break;
                #endif /* NO_RSA */
                #ifdef HAVE_NTRU
                case NTRUk:
                    oid = keyNtruOid;
                    *oidSz = sizeof(keyNtruOid);
                    break;
                #endif /* HAVE_NTRU */
                #ifdef HAVE_ECC
                case ECDSAk:
                    oid = keyEcdsaOid;
                    *oidSz = sizeof(keyEcdsaOid);
                    break;
                #endif /* HAVE_ECC */
                default:
                    break;
            }
            break;

        #ifdef HAVE_ECC
        case oidCurveType:
            if (wc_ecc_get_oid(id, &oid, oidSz) < 0) {
                WOLFSSL_MSG("ECC OID not found");
            }
            break;
        #endif /* HAVE_ECC */

        case oidBlkType:
            switch (id) {
                case DESb:
                    oid = blkDesCbcOid;
                    *oidSz = sizeof(blkDesCbcOid);
                    break;
                case DES3b:
                    oid = blkDes3CbcOid;
                    *oidSz = sizeof(blkDes3CbcOid);
                    break;
            }
            break;

        #ifdef HAVE_OCSP
        case oidOcspType:
            switch (id) {
                case OCSP_BASIC_OID:
                    oid = ocspBasicOid;
                    *oidSz = sizeof(ocspBasicOid);
                    break;
                case OCSP_NONCE_OID:
                    oid = ocspNonceOid;
                    *oidSz = sizeof(ocspNonceOid);
                    break;
            }
            break;
        #endif /* HAVE_OCSP */

        case oidCertExtType:
            switch (id) {
                case BASIC_CA_OID:
                    oid = extBasicCaOid;
                    *oidSz = sizeof(extBasicCaOid);
                    break;
                case ALT_NAMES_OID:
                    oid = extAltNamesOid;
                    *oidSz = sizeof(extAltNamesOid);
                    break;
                case CRL_DIST_OID:
                    oid = extCrlDistOid;
                    *oidSz = sizeof(extCrlDistOid);
                    break;
                case AUTH_INFO_OID:
                    oid = extAuthInfoOid;
                    *oidSz = sizeof(extAuthInfoOid);
                    break;
                case AUTH_KEY_OID:
                    oid = extAuthKeyOid;
                    *oidSz = sizeof(extAuthKeyOid);
                    break;
                case SUBJ_KEY_OID:
                    oid = extSubjKeyOid;
                    *oidSz = sizeof(extSubjKeyOid);
                    break;
                case CERT_POLICY_OID:
                    oid = extCertPolicyOid;
                    *oidSz = sizeof(extCertPolicyOid);
                    break;
                case KEY_USAGE_OID:
                    oid = extKeyUsageOid;
                    *oidSz = sizeof(extKeyUsageOid);
                    break;
                case INHIBIT_ANY_OID:
                    oid = extInhibitAnyOid;
                    *oidSz = sizeof(extInhibitAnyOid);
                    break;
                case EXT_KEY_USAGE_OID:
                    oid = extExtKeyUsageOid;
                    *oidSz = sizeof(extExtKeyUsageOid);
                    break;
                case NAME_CONS_OID:
                    oid = extNameConsOid;
                    *oidSz = sizeof(extNameConsOid);
                    break;
            }
            break;

        case oidCertAuthInfoType:
            switch (id) {
                case AIA_OCSP_OID:
                    oid = extAuthInfoOcspOid;
                    *oidSz = sizeof(extAuthInfoOcspOid);
                    break;
                case AIA_CA_ISSUER_OID:
                    oid = extAuthInfoCaIssuerOid;
                    *oidSz = sizeof(extAuthInfoCaIssuerOid);
                    break;
            }
            break;

        case oidCertPolicyType:
            switch (id) {
                case CP_ANY_OID:
                    oid = extCertPolicyAnyOid;
                    *oidSz = sizeof(extCertPolicyAnyOid);
                    break;
            }
            break;

        case oidCertAltNameType:
            switch (id) {
                case HW_NAME_OID:
                    oid = extAltNamesHwNameOid;
                    *oidSz = sizeof(extAltNamesHwNameOid);
                    break;
            }
            break;

        case oidCertKeyUseType:
            switch (id) {
                case EKU_ANY_OID:
                    oid = extExtKeyUsageAnyOid;
                    *oidSz = sizeof(extExtKeyUsageAnyOid);
                    break;
                case EKU_SERVER_AUTH_OID:
                    oid = extExtKeyUsageServerAuthOid;
                    *oidSz = sizeof(extExtKeyUsageServerAuthOid);
                    break;
                case EKU_CLIENT_AUTH_OID:
                    oid = extExtKeyUsageClientAuthOid;
                    *oidSz = sizeof(extExtKeyUsageClientAuthOid);
                    break;
                case EKU_OCSP_SIGN_OID:
                    oid = extExtKeyUsageOcspSignOid;
                    *oidSz = sizeof(extExtKeyUsageOcspSignOid);
                    break;
            }

        case oidKdfType:
            switch (id) {
                case PBKDF2_OID:
                    oid = pbkdf2Oid;
                    *oidSz = sizeof(pbkdf2Oid);
                    break;
            }
            break;

        case oidIgnoreType:
        default:
            break;
    }

    return oid;
}

#ifdef HAVE_OID_ENCODING
int EncodeObjectId(const word16* in, word32 inSz, byte* out, word32* outSz)
{
    int i, x, len;
    word32 d, t;

    /* check args */
    if (in == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* compute length of encoded OID */
    d = (in[0] * 40) + in[1];
    len = 0;
    for (i = 1; i < (int)inSz; i++) {
        x = 0;
        t = d;
        while (t) {
            x++;
            t >>= 1;
        }
        len += (x / 7) + ((x % 7) ? 1 : 0) + (d == 0 ? 1 : 0);

        if (i < (int)inSz - 1) {
            d = in[i + 1];
        }
    }

    if (out) {
        /* verify length */
        if ((int)*outSz < len) {
            return BUFFER_E; /* buffer provided is not large enough */
        }

        /* calc first byte */
        d = (in[0] * 40) + in[1];

        /* encode bytes */
        x = 0;
        for (i = 1; i < (int)inSz; i++) {
            if (d) {
                int y = x, z;
                byte mask = 0;
                while (d) {
                    out[x++] = (byte)((d & 0x7F) | mask);
                    d     >>= 7;
                    mask  |= 0x80;  /* upper bit is set on all but the last byte */
                }
                /* now swap bytes y...x-1 */
                z = x - 1;
                while (y < z) {
                    mask = out[y];
                    out[y] = out[z];
                    out[z] = mask;
                    ++y;
                    --z;
                }
            }
            else {
              out[x++] = 0x00; /* zero value */
            }

            /* next word */
            if (i < (int)inSz - 1) {
                d = in[i + 1];
            }
        }
    }

    /* return length */
    *outSz = len;

    return 0;
}
#endif /* HAVE_OID_ENCODING */

#ifdef HAVE_OID_DECODING
int DecodeObjectId(const byte* in, word32 inSz, word16* out, word32* outSz)
{
    int x = 0, y = 0;
    word32 t = 0;

    /* check args */
    if (in == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* decode bytes */
    while (inSz--) {
        t = (t << 7) | (in[x] & 0x7F);
        if (!(in[x] & 0x80)) {
            if (y >= (int)*outSz) {
                return BUFFER_E;
            }
            if (y == 0) {
                out[0] = (t / 40);
                out[1] = (t % 40);
                y = 2;
            }
            else {
                out[y++] = t;
            }
            t = 0; /* reset tmp */
        }
        x++;
    }

    /* return length */
    *outSz = y;

    return 0;
}
#endif /* HAVE_OID_DECODING */

int GetObjectId(const byte* input, word32* inOutIdx, word32* oid,
                                  word32 oidType, word32 maxIdx)
{
    int    length;
    word32 i = *inOutIdx;
#ifndef NO_VERIFY_OID
    word32 actualOidSz = 0;
    const byte* actualOid;
#endif /* NO_VERIFY_OID */
    byte   b;

    (void)oidType;
    WOLFSSL_ENTER("GetObjectId()");
    *oid = 0;

    b = input[i++];
    if (b != ASN_OBJECT_ID)
        return ASN_OBJECT_ID_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

#ifndef NO_VERIFY_OID
    actualOid = &input[i];
    if (length > 0)
        actualOidSz = (word32)length;
#endif /* NO_VERIFY_OID */

    while(length--) {
        /* odd HC08 compiler behavior here when input[i++] */
        *oid += input[i];
        i++;
    }
    /* just sum it up for now */

    *inOutIdx = i;

#ifndef NO_VERIFY_OID
    {
        const byte* checkOid = NULL;
        word32 checkOidSz;

        if (oidType != oidIgnoreType) {
            checkOid = OidFromId(*oid, oidType, &checkOidSz);

        #if 0
            /* support for dumping OID information */
            printf("OID (Type %d, Sz %d, Sum %d): ", oidType, actualOidSz, *oid);
            for (i=0; i<actualOidSz; i++) {
                printf("%d, ", actualOid[i]);
            }
            printf("\n");
            #ifdef HAVE_OID_DECODING
            {
                int ret;
                word16 decOid[16];
                word32 decOidSz = sizeof(decOid);
                ret = DecodeObjectId(actualOid, actualOidSz, decOid, &decOidSz);
                if (ret == 0) {
                    printf("  Decoded (Sz %d): ", decOidSz);
                    for (i=0; i<decOidSz; i++) {
                        printf("%d.", decOid[i]);
                    }
                    printf("\n");
                }
                else {
                    printf("DecodeObjectId failed: %d\n", ret);
                }
            }
            #endif /* HAVE_OID_DECODING */
        #endif

            if (checkOid != NULL && 
                (checkOidSz != actualOidSz ||
                    XMEMCMP(actualOid, checkOid, checkOidSz) != 0)) {
                WOLFSSL_MSG("OID Check Failed");
                return ASN_UNKNOWN_OID_E;
            }
        }
    }
#endif /* NO_VERIFY_OID */

    return 0;
}


#ifndef NO_RSA
#ifndef HAVE_USER_RSA
#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
static int SkipObjectId(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    int    length;

    if (input[(*inOutIdx)++] != ASN_OBJECT_ID)
        return ASN_OBJECT_ID_E;

    if (GetLength(input, inOutIdx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *inOutIdx += length;

    return 0;
}
#endif /* OPENSSL_EXTRA || RSA_DECODE_EXTRA */
#endif /* !HAVE_USER_RSA */
#endif /* !NO_RSA */

WOLFSSL_LOCAL int GetAlgoId(const byte* input, word32* inOutIdx, word32* oid,
                     word32 oidType, word32 maxIdx)
{
    int    length;
    word32 i = *inOutIdx;
    byte   b;
    *oid = 0;

    WOLFSSL_ENTER("GetAlgoId");

    if (GetSequence(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetObjectId(input, &i, oid, oidType, maxIdx) < 0)
        return ASN_OBJECT_ID_E;

    /* could have NULL tag and 0 terminator, but may not */
    b = input[i];

    if (b == ASN_TAG_NULL) {
        i++;
        b = input[i++];
        if (b != 0)
            return ASN_EXPECT_0_E;
    }

    *inOutIdx = i;

    return 0;
}

#ifndef NO_RSA

#ifndef HAVE_USER_RSA
int wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                        word32 inSz)
{
    int version, length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetIntRsa(key, &key->n,  input, inOutIdx, inSz) < 0 ||
        GetIntRsa(key, &key->e,  input, inOutIdx, inSz) < 0 ||
        GetIntRsa(key, &key->d,  input, inOutIdx, inSz) < 0 ||
        GetIntRsa(key, &key->p,  input, inOutIdx, inSz) < 0 ||
        GetIntRsa(key, &key->q,  input, inOutIdx, inSz) < 0 ||
        GetIntRsa(key, &key->dP, input, inOutIdx, inSz) < 0 ||
        GetIntRsa(key, &key->dQ, input, inOutIdx, inSz) < 0 ||
        GetIntRsa(key, &key->u,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}
#endif /* HAVE_USER_RSA */
#endif /* NO_RSA */

/* Remove PKCS8 header, move beginning of traditional to beginning of input */
int ToTraditional(byte* input, word32 sz)
{
    word32 inOutIdx = 0, oid;
    int    version, length;

    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, &inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(input, &inOutIdx, &oid, oidKeyType, sz) < 0)
        return ASN_PARSE_E;

    if (input[inOutIdx] == ASN_OBJECT_ID) {
        /* pkcs8 ecc uses slightly different format */
        inOutIdx++;  /* past id */
        if (GetLength(input, &inOutIdx, &length, sz) < 0)
            return ASN_PARSE_E;
        inOutIdx += length;  /* over sub id, key input will verify */
    }

    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    XMEMMOVE(input, input + inOutIdx, length);

    return length;
}


#ifndef NO_PWDBASED

/* Check To see if PKCS version algo is supported, set id if it is return 0
   < 0 on error */
static int CheckAlgo(int first, int second, int* id, int* version)
{
    *id      = ALGO_ID_E;
    *version = PKCS5;   /* default */

    if (first == 1) {
        switch (second) {
        case 1:
            *id = PBE_SHA1_RC4_128;
            *version = PKCS12;
            return 0;
        case 3:
            *id = PBE_SHA1_DES3;
            *version = PKCS12;
            return 0;
        default:
            return ALGO_ID_E;
        }
    }

    if (first != PKCS5)
        return ASN_INPUT_E;  /* VERSION ERROR */

    if (second == PBES2) {
        *version = PKCS5v2;
        return 0;
    }

    switch (second) {
    case 3:                   /* see RFC 2898 for ids */
        *id = PBE_MD5_DES;
        return 0;
    case 10:
        *id = PBE_SHA1_DES;
        return 0;
    default:
        return ALGO_ID_E;

    }
}


/* Check To see if PKCS v2 algo is supported, set id if it is return 0
   < 0 on error */
static int CheckAlgoV2(int oid, int* id)
{
    switch (oid) {
    case 69:
        *id = PBE_SHA1_DES;
        return 0;
    case 652:
        *id = PBE_SHA1_DES3;
        return 0;
    default:
        return ALGO_ID_E;

    }
}


/* Decrypt input in place from parameters based on id */
static int DecryptKey(const char* password, int passwordSz, byte* salt,
                      int saltSz, int iterations, int id, byte* input,
                      int length, int version, byte* cbcIv)
{
    int typeH;
    int derivedLen;
    int decryptionType;
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* key;
#else
    byte key[MAX_KEY_SIZE];
#endif

    (void)input;
    (void)length;

    switch (id) {
        case PBE_MD5_DES:
            typeH = MD5;
            derivedLen = 16;           /* may need iv for v1.5 */
            decryptionType = DES_TYPE;
            break;

        case PBE_SHA1_DES:
            typeH = SHA;
            derivedLen = 16;           /* may need iv for v1.5 */
            decryptionType = DES_TYPE;
            break;

        case PBE_SHA1_DES3:
            typeH = SHA;
            derivedLen = 32;           /* may need iv for v1.5 */
            decryptionType = DES3_TYPE;
            break;

        case PBE_SHA1_RC4_128:
            typeH = SHA;
            derivedLen = 16;
            decryptionType = RC4_TYPE;
            break;

        default:
            return ALGO_ID_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    key = (byte*)XMALLOC(MAX_KEY_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL)
        return MEMORY_E;
#endif

    if (version == PKCS5v2)
        ret = wc_PBKDF2(key, (byte*)password, passwordSz,
                        salt, saltSz, iterations, derivedLen, typeH);
#ifndef NO_SHA
    else if (version == PKCS5)
        ret = wc_PBKDF1(key, (byte*)password, passwordSz,
                        salt, saltSz, iterations, derivedLen, typeH);
#endif
    else if (version == PKCS12) {
        int  i, idx = 0;
        byte unicodePasswd[MAX_UNICODE_SZ];

        if ( (passwordSz * 2 + 2) > (int)sizeof(unicodePasswd)) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return UNICODE_SIZE_E;
        }

        for (i = 0; i < passwordSz; i++) {
            unicodePasswd[idx++] = 0x00;
            unicodePasswd[idx++] = (byte)password[i];
        }
        /* add trailing NULL */
        unicodePasswd[idx++] = 0x00;
        unicodePasswd[idx++] = 0x00;

        ret =  wc_PKCS12_PBKDF(key, unicodePasswd, idx, salt, saltSz,
                            iterations, derivedLen, typeH, 1);
        if (decryptionType != RC4_TYPE)
            ret += wc_PKCS12_PBKDF(cbcIv, unicodePasswd, idx, salt, saltSz,
                                iterations, 8, typeH, 2);
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ALGO_ID_E;
    }

    if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    switch (decryptionType) {
#ifndef NO_DES3
        case DES_TYPE:
        {
            Des    dec;
            byte*  desIv = key + 8;

            if (version == PKCS5v2 || version == PKCS12)
                desIv = cbcIv;

            ret = wc_Des_SetKey(&dec, key, desIv, DES_DECRYPTION);
            if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }

            wc_Des_CbcDecrypt(&dec, input, input, length);
            break;
        }

        case DES3_TYPE:
        {
            Des3   dec;
            byte*  desIv = key + 24;

            if (version == PKCS5v2 || version == PKCS12)
                desIv = cbcIv;
            ret = wc_Des3_SetKey(&dec, key, desIv, DES_DECRYPTION);
            if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }
            ret = wc_Des3_CbcDecrypt(&dec, input, input, length);
            if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ret;
            }
            break;
        }
#endif
#ifndef NO_RC4
        case RC4_TYPE:
        {
            Arc4    dec;

            wc_Arc4SetKey(&dec, key, derivedLen);
            wc_Arc4Process(&dec, input, input, length);
            break;
        }
#endif

        default:
#ifdef WOLFSSL_SMALL_STACK
            XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ALGO_ID_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return 0;
}


/* Remove Encrypted PKCS8 header, move beginning of traditional to beginning
   of input */
int ToTraditionalEnc(byte* input, word32 sz,const char* password,int passwordSz)
{
    word32 inOutIdx = 0, oid;
    int    first, second, length, version, saltSz, id;
    int    iterations = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte*  salt = NULL;
    byte*  cbcIv = NULL;
#else
    byte   salt[MAX_SALT_SIZE];
    byte   cbcIv[MAX_IV_SIZE];
#endif

    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(input, &inOutIdx, &oid, oidSigType, sz) < 0)
        return ASN_PARSE_E;

    first  = input[inOutIdx - 2];   /* PKCS version always 2nd to last byte */
    second = input[inOutIdx - 1];   /* version.algo, algo id last byte */

    if (CheckAlgo(first, second, &id, &version) < 0)
        return ASN_INPUT_E;  /* Algo ID error */

    if (version == PKCS5v2) {

        if (GetSequence(input, &inOutIdx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (GetAlgoId(input, &inOutIdx, &oid, oidKdfType, sz) < 0)
            return ASN_PARSE_E;

        if (oid != PBKDF2_OID)
            return ASN_PARSE_E;
    }

    if (GetSequence(input, &inOutIdx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(input, &inOutIdx, &saltSz, sz) < 0)
        return ASN_PARSE_E;

    if (saltSz > MAX_SALT_SIZE)
        return ASN_PARSE_E;

#ifdef WOLFSSL_SMALL_STACK
    salt = (byte*)XMALLOC(MAX_SALT_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (salt == NULL)
        return MEMORY_E;
#endif

    XMEMCPY(salt, &input[inOutIdx], saltSz);
    inOutIdx += saltSz;

    if (GetShortInt(input, &inOutIdx, &iterations) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    cbcIv = (byte*)XMALLOC(MAX_IV_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cbcIv == NULL) {
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (version == PKCS5v2) {
        /* get encryption algo */
        /* JOHN: New type. Need a little more research. */
        if (GetAlgoId(input, &inOutIdx, &oid, oidBlkType, sz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }

        if (CheckAlgoV2(oid, &id) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;  /* PKCS v2 algo id error */
        }

        if (input[inOutIdx++] != ASN_OCTET_STRING) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }

        if (GetLength(input, &inOutIdx, &length, sz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ASN_PARSE_E;
        }

        XMEMCPY(cbcIv, &input[inOutIdx], length);
        inOutIdx += length;
    }

    if (input[inOutIdx++] != ASN_OCTET_STRING) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (GetLength(input, &inOutIdx, &length, sz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    if (DecryptKey(password, passwordSz, salt, saltSz, iterations, id,
                   input + inOutIdx, length, version, cbcIv) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_INPUT_E;  /* decrypt failure */
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(salt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    XMEMMOVE(input, input + inOutIdx, length);
    return ToTraditional(input, length);
}

#endif /* NO_PWDBASED */

#ifndef NO_RSA

#ifndef HAVE_USER_RSA
int wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                       word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PUBLIC;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    {
    byte b = input[*inOutIdx];
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (SkipObjectId(input, inOutIdx, inSz) < 0)
            return ASN_PARSE_E;

        /* could have NULL tag and 0 terminator, but may not */
        b = input[(*inOutIdx)++];

        if (b == ASN_TAG_NULL) {
            b = input[(*inOutIdx)++];
            if (b != 0)
                return ASN_EXPECT_0_E;
        }
        else
        /* go back, didn't have it */
            (*inOutIdx)--;

        /* should have bit tag length and seq next */
        b = input[(*inOutIdx)++];
        if (b != ASN_BIT_STRING)
            return ASN_BITSTR_E;

        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        /* could have 0 */
        b = input[(*inOutIdx)++];
        if (b != 0)
            (*inOutIdx)--;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
    }  /* end if */
    }  /* openssl var block */
#endif /* OPENSSL_EXTRA */

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}

/* import RSA public key elements (n, e) into RsaKey structure (key) */
int wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz, const byte* e,
                             word32 eSz, RsaKey* key)
{
    if (n == NULL || e == NULL || key == NULL)
        return BAD_FUNC_ARG;

    key->type = RSA_PUBLIC;

    if (mp_init(&key->n) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&key->n, n, nSz) != 0) {
        mp_clear(&key->n);
        return ASN_GETINT_E;
    }

    if (mp_init(&key->e) != MP_OKAY) {
        mp_clear(&key->n);
        return MP_INIT_E;
    }

    if (mp_read_unsigned_bin(&key->e, e, eSz) != 0) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ASN_GETINT_E;
    }

    return 0;
}
#endif /* HAVE_USER_RSA */
#endif

#ifndef NO_DH

int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->g,  input, inOutIdx, inSz) < 0 )  return ASN_DH_KEY_E;

    return 0;
}


int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p, word32* pInOutSz,
                 byte* g, word32* gInOutSz)
{
    word32 i = 0;
    byte   b;
    int    length;

    if (GetSequence(input, &i, &length, inSz) < 0)
        return ASN_PARSE_E;

    b = input[i++];
    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, inSz) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    if (length <= (int)*pInOutSz) {
        XMEMCPY(p, &input[i], length);
        *pInOutSz = length;
    }
    else
        return BUFFER_E;

    i += length;

    b = input[i++];
    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (length <= (int)*gInOutSz) {
        XMEMCPY(g, &input[i], length);
        *gInOutSz = length;
    }
    else
        return BUFFER_E;

    return 0;
}

#endif /* NO_DH */


#ifndef NO_DSA

int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->g,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->y,  input, inOutIdx, inSz) < 0 )
        return ASN_DH_KEY_E;

    key->type = DSA_PUBLIC;
    return 0;
}


int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    int    length, version;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->g,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->y,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->x,  input, inOutIdx, inSz) < 0 )
        return ASN_DH_KEY_E;

    key->type = DSA_PRIVATE;
    return 0;
}

static mp_int* GetDsaInt(DsaKey* key, int idx)
{
    if (idx == 0)
        return &key->p;
    if (idx == 1)
        return &key->q;
    if (idx == 2)
        return &key->g;
    if (idx == 3)
        return &key->y;
    if (idx == 4)
        return &key->x;

    return NULL;
}

/* Release Tmp DSA resources */
static INLINE void FreeTmpDsas(byte** tmps, void* heap)
{
    int i;

    for (i = 0; i < DSA_INTS; i++)
        XFREE(tmps[i], heap, DYNAMIC_TYPE_DSA);

    (void)heap;
}

/* Convert DsaKey key to DER format, write to output (inLen), return bytes
 written */
int wc_DsaKeyToDer(DsaKey* key, byte* output, word32 inLen)
{
    word32 seqSz, verSz, rawLen, intTotalLen = 0;
    word32 sizes[DSA_INTS];
    int    i, j, outLen, ret = 0, lbit;

    byte  seq[MAX_SEQ_SZ];
    byte  ver[MAX_VERSION_SZ];
    byte* tmps[DSA_INTS];

    if (!key || !output)
        return BAD_FUNC_ARG;

    if (key->type != DSA_PRIVATE)
        return BAD_FUNC_ARG;

    for (i = 0; i < DSA_INTS; i++)
        tmps[i] = NULL;

    /* write all big ints from key to DER tmps */
    for (i = 0; i < DSA_INTS; i++) {
        mp_int* keyInt = GetDsaInt(key, i);

        /* leading zero */
        lbit = mp_leading_bit(keyInt);
        rawLen = mp_unsigned_bin_size(keyInt) + lbit;

        tmps[i] = (byte*)XMALLOC(rawLen + MAX_SEQ_SZ, key->heap,
                                                              DYNAMIC_TYPE_DSA);
        if (tmps[i] == NULL) {
            ret = MEMORY_E;
            break;
        }

        tmps[i][0] = ASN_INTEGER;
        sizes[i] = SetLength(rawLen, tmps[i] + 1) + 1 + lbit; /* tag & lbit */

        if (sizes[i] <= MAX_SEQ_SZ) {
            int err;

            /* leading zero */
            if (lbit)
                tmps[i][sizes[i]-1] = 0x00;

            err = mp_to_unsigned_bin(keyInt, tmps[i] + sizes[i]);
            if (err == MP_OKAY) {
                sizes[i] += (rawLen-lbit); /* lbit included in rawLen */
                intTotalLen += sizes[i];
            }
            else {
                ret = err;
                break;
            }
        }
        else {
            ret = ASN_INPUT_E;
            break;
        }
    }

    if (ret != 0) {
        FreeTmpDsas(tmps, key->heap);
        return ret;
    }

    /* make headers */
    verSz = SetMyVersion(0, ver, FALSE);
    seqSz = SetSequence(verSz + intTotalLen, seq);

    outLen = seqSz + verSz + intTotalLen;
    if (outLen > (int)inLen)
        return BAD_FUNC_ARG;

    /* write to output */
    XMEMCPY(output, seq, seqSz);
    j = seqSz;
    XMEMCPY(output + j, ver, verSz);
    j += verSz;

    for (i = 0; i < DSA_INTS; i++) {
        XMEMCPY(output + j, tmps[i], sizes[i]);
        j += sizes[i];
    }
    FreeTmpDsas(tmps, key->heap);

    return outLen;
}

#endif /* NO_DSA */


void InitDecodedCert(DecodedCert* cert, byte* source, word32 inSz, void* heap)
{
    cert->publicKey       = 0;
    cert->pubKeySize      = 0;
    cert->pubKeyStored    = 0;
    cert->version         = 0;
    cert->signature       = 0;
    cert->subjectCN       = 0;
    cert->subjectCNLen    = 0;
    cert->subjectCNEnc    = CTC_UTF8;
    cert->subjectCNStored = 0;
    cert->weOwnAltNames   = 0;
    cert->altNames        = NULL;
#ifndef IGNORE_NAME_CONSTRAINTS
    cert->altEmailNames   = NULL;
    cert->permittedNames  = NULL;
    cert->excludedNames   = NULL;
#endif /* IGNORE_NAME_CONSTRAINTS */
    cert->issuer[0]       = '\0';
    cert->subject[0]      = '\0';
    cert->source          = source;  /* don't own */
    cert->srcIdx          = 0;
    cert->maxIdx          = inSz;    /* can't go over this index */
    cert->heap            = heap;
    XMEMSET(cert->serial, 0, EXTERNAL_SERIAL_SIZE);
    cert->serialSz        = 0;
    cert->extensions      = 0;
    cert->extensionsSz    = 0;
    cert->extensionsIdx   = 0;
    cert->extAuthInfo     = NULL;
    cert->extAuthInfoSz   = 0;
    cert->extCrlInfo      = NULL;
    cert->extCrlInfoSz    = 0;
    XMEMSET(cert->extSubjKeyId, 0, KEYID_SIZE);
    cert->extSubjKeyIdSet = 0;
    XMEMSET(cert->extAuthKeyId, 0, KEYID_SIZE);
    cert->extAuthKeyIdSet = 0;
    cert->extKeyUsageSet  = 0;
    cert->extKeyUsage     = 0;
    cert->extExtKeyUsageSet = 0;
    cert->extExtKeyUsage    = 0;
    cert->isCA            = 0;
    cert->pathLengthSet   = 0;
    cert->pathLength      = 0;
#ifdef HAVE_PKCS7
    cert->issuerRaw       = NULL;
    cert->issuerRawLen    = 0;
#endif
#ifdef WOLFSSL_CERT_GEN
    cert->subjectSN       = 0;
    cert->subjectSNLen    = 0;
    cert->subjectSNEnc    = CTC_UTF8;
    cert->subjectC        = 0;
    cert->subjectCLen     = 0;
    cert->subjectCEnc     = CTC_PRINTABLE;
    cert->subjectL        = 0;
    cert->subjectLLen     = 0;
    cert->subjectLEnc     = CTC_UTF8;
    cert->subjectST       = 0;
    cert->subjectSTLen    = 0;
    cert->subjectSTEnc    = CTC_UTF8;
    cert->subjectO        = 0;
    cert->subjectOLen     = 0;
    cert->subjectOEnc     = CTC_UTF8;
    cert->subjectOU       = 0;
    cert->subjectOULen    = 0;
    cert->subjectOUEnc    = CTC_UTF8;
    cert->subjectEmail    = 0;
    cert->subjectEmailLen = 0;
#endif /* WOLFSSL_CERT_GEN */
    cert->beforeDate      = NULL;
    cert->beforeDateLen   = 0;
    cert->afterDate       = NULL;
    cert->afterDateLen    = 0;
#ifdef OPENSSL_EXTRA
    XMEMSET(&cert->issuerName, 0, sizeof(DecodedName));
    XMEMSET(&cert->subjectName, 0, sizeof(DecodedName));
    cert->extBasicConstSet = 0;
    cert->extBasicConstCrit = 0;
    cert->extSubjAltNameSet = 0;
    cert->extSubjAltNameCrit = 0;
    cert->extAuthKeyIdCrit = 0;
    cert->extSubjKeyIdCrit = 0;
    cert->extKeyUsageCrit = 0;
    cert->extExtKeyUsageCrit = 0;
    cert->extExtKeyUsageSrc = NULL;
    cert->extExtKeyUsageSz = 0;
    cert->extExtKeyUsageCount = 0;
    cert->extAuthKeyIdSrc = NULL;
    cert->extAuthKeyIdSz = 0;
    cert->extSubjKeyIdSrc = NULL;
    cert->extSubjKeyIdSz = 0;
#endif /* OPENSSL_EXTRA */
#if defined(OPENSSL_EXTRA) || !defined(IGNORE_NAME_CONSTRAINTS)
    cert->extNameConstraintSet = 0;
#endif /* OPENSSL_EXTRA || !IGNORE_NAME_CONSTRAINTS */
#ifdef HAVE_ECC
    cert->pkCurveOID = 0;
#endif /* HAVE_ECC */
#ifdef WOLFSSL_SEP
    cert->deviceTypeSz = 0;
    cert->deviceType = NULL;
    cert->hwTypeSz = 0;
    cert->hwType = NULL;
    cert->hwSerialNumSz = 0;
    cert->hwSerialNum = NULL;
    #ifdef OPENSSL_EXTRA
        cert->extCertPolicySet = 0;
        cert->extCertPolicyCrit = 0;
    #endif /* OPENSSL_EXTRA */
#endif /* WOLFSSL_SEP */
#ifdef WOLFSSL_CERT_EXT
    XMEMSET(cert->extCertPolicies, 0, MAX_CERTPOL_NB*MAX_CERTPOL_SZ);
    cert->extCertPoliciesNb = 0;
#endif
}


void FreeAltNames(DNS_entry* altNames, void* heap)
{
    (void)heap;

    while (altNames) {
        DNS_entry* tmp = altNames->next;

        XFREE(altNames->name, heap, DYNAMIC_TYPE_ALTNAME);
        XFREE(altNames,       heap, DYNAMIC_TYPE_ALTNAME);
        altNames = tmp;
    }
}

#ifndef IGNORE_NAME_CONSTRAINTS

void FreeNameSubtrees(Base_entry* names, void* heap)
{
    (void)heap;

    while (names) {
        Base_entry* tmp = names->next;

        XFREE(names->name, heap, DYNAMIC_TYPE_ALTNAME);
        XFREE(names,       heap, DYNAMIC_TYPE_ALTNAME);
        names = tmp;
    }
}

#endif /* IGNORE_NAME_CONSTRAINTS */

void FreeDecodedCert(DecodedCert* cert)
{
    if (cert->subjectCNStored == 1)
        XFREE(cert->subjectCN, cert->heap, DYNAMIC_TYPE_SUBJECT_CN);
    if (cert->pubKeyStored == 1)
        XFREE(cert->publicKey, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (cert->weOwnAltNames && cert->altNames)
        FreeAltNames(cert->altNames, cert->heap);
#ifndef IGNORE_NAME_CONSTRAINTS
    if (cert->altEmailNames)
        FreeAltNames(cert->altEmailNames, cert->heap);
    if (cert->permittedNames)
        FreeNameSubtrees(cert->permittedNames, cert->heap);
    if (cert->excludedNames)
        FreeNameSubtrees(cert->excludedNames, cert->heap);
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef WOLFSSL_SEP
    XFREE(cert->deviceType, cert->heap, DYNAMIC_TYPE_X509_EXT);
    XFREE(cert->hwType, cert->heap, DYNAMIC_TYPE_X509_EXT);
    XFREE(cert->hwSerialNum, cert->heap, DYNAMIC_TYPE_X509_EXT);
#endif /* WOLFSSL_SEP */
#ifdef OPENSSL_EXTRA
    if (cert->issuerName.fullName != NULL)
        XFREE(cert->issuerName.fullName, cert->heap, DYNAMIC_TYPE_X509);
    if (cert->subjectName.fullName != NULL)
        XFREE(cert->subjectName.fullName, cert->heap, DYNAMIC_TYPE_X509);
#endif /* OPENSSL_EXTRA */
}

#ifndef NO_ASN_TIME
static int GetCertHeader(DecodedCert* cert)
{
    int ret = 0, len;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->certBegin = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;
    cert->sigIndex = len + cert->srcIdx;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &cert->version) < 0)
        return ASN_PARSE_E;

    if (GetSerialNumber(cert->source, &cert->srcIdx, cert->serial,
                                        &cert->serialSz, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    return ret;
}

#if !defined(NO_RSA)
/* Store Rsa Key, may save later, Dsa could use in future */
static int StoreRsaKey(DecodedCert* cert)
{
    int    length;
    word32 recvd = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    recvd = cert->srcIdx - recvd;
    length += recvd;

    while (recvd--)
       cert->srcIdx--;

    cert->pubKeySize = length;
    cert->publicKey = cert->source + cert->srcIdx;
    cert->srcIdx += length;

    return 0;
}
#endif
#endif /* !NO_ASN_TIME */


#ifdef HAVE_ECC

    /* return 0 on success if the ECC curve oid sum is supported */
    static int CheckCurve(word32 oid)
    {
        int ret = 0;
        word32 oidSz = 0;

        ret = wc_ecc_get_oid(oid, NULL, &oidSz);
        if (ret < 0 || oidSz <= 0) {
            WOLFSSL_MSG("CheckCurve not found");
            ret = ALGO_ID_E;
        }

        return ret;
    }

#endif /* HAVE_ECC */

#ifndef NO_ASN_TIME
static int GetKey(DecodedCert* cert)
{
    int length;
#ifdef HAVE_NTRU
    int tmpIdx = cert->srcIdx;
#endif

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(cert->source, &cert->srcIdx,
                  &cert->keyOID, oidKeyType, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    switch (cert->keyOID) {
   #ifndef NO_RSA
        case RSAk:
        {
            byte b = cert->source[cert->srcIdx++];
            if (b != ASN_BIT_STRING)
                return ASN_BITSTR_E;

            if (GetLength(cert->source,&cert->srcIdx,&length,cert->maxIdx) < 0)
                return ASN_PARSE_E;
            b = cert->source[cert->srcIdx++];
            if (b != 0x00)
                return ASN_EXPECT_0_E;

            return StoreRsaKey(cert);
        }

    #endif /* NO_RSA */
    #ifdef HAVE_NTRU
        case NTRUk:
        {
            const byte* key = &cert->source[tmpIdx];
            byte*       next = (byte*)key;
            word16      keyLen;
            word32      rc;
            word32      remaining = cert->maxIdx - cert->srcIdx;
#ifdef WOLFSSL_SMALL_STACK
            byte*       keyBlob = NULL;
#else
            byte        keyBlob[MAX_NTRU_KEY_SZ];
#endif
            rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key,
                                &keyLen, NULL, &next, &remaining);
            if (rc != NTRU_OK)
                return ASN_NTRU_KEY_E;
            if (keyLen > MAX_NTRU_KEY_SZ)
                return ASN_NTRU_KEY_E;

#ifdef WOLFSSL_SMALL_STACK
            keyBlob = (byte*)XMALLOC(MAX_NTRU_KEY_SZ, NULL,
                                     DYNAMIC_TYPE_TMP_BUFFER);
            if (keyBlob == NULL)
                return MEMORY_E;
#endif

            rc = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key,
                                &keyLen, keyBlob, &next, &remaining);
            if (rc != NTRU_OK) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ASN_NTRU_KEY_E;
            }

            if ( (next - key) < 0) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ASN_NTRU_KEY_E;
            }

            cert->srcIdx = tmpIdx + (int)(next - key);

            cert->publicKey = (byte*) XMALLOC(keyLen, cert->heap,
                                              DYNAMIC_TYPE_PUBLIC_KEY);
            if (cert->publicKey == NULL) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return MEMORY_E;
            }
            XMEMCPY(cert->publicKey, keyBlob, keyLen);
            cert->pubKeyStored = 1;
            cert->pubKeySize   = keyLen;

#ifdef WOLFSSL_SMALL_STACK
            XFREE(keyBlob, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

            return 0;
        }
    #endif /* HAVE_NTRU */
    #ifdef HAVE_ECC
        case ECDSAk:
        {
            byte b;

            if (GetObjectId(cert->source, &cert->srcIdx,
                            &cert->pkCurveOID, oidCurveType, cert->maxIdx) < 0)
                return ASN_PARSE_E;

            if (CheckCurve(cert->pkCurveOID) < 0)
                return ECC_CURVE_OID_E;

            /* key header */
            b = cert->source[cert->srcIdx++];
            if (b != ASN_BIT_STRING)
                return ASN_BITSTR_E;

            if (GetLength(cert->source,&cert->srcIdx,&length,cert->maxIdx) < 0)
                return ASN_PARSE_E;
            b = cert->source[cert->srcIdx++];
            if (b != 0x00)
                return ASN_EXPECT_0_E;

            /* actual key, use length - 1 since ate preceding 0 */
            length -= 1;

            cert->publicKey = (byte*) XMALLOC(length, cert->heap,
                                              DYNAMIC_TYPE_PUBLIC_KEY);
            if (cert->publicKey == NULL)
                return MEMORY_E;
            XMEMCPY(cert->publicKey, &cert->source[cert->srcIdx], length);
            cert->pubKeyStored = 1;
            cert->pubKeySize   = length;

            cert->srcIdx += length;

            return 0;
        }
    #endif /* HAVE_ECC */
        default:
            return ASN_UNKNOWN_OID_E;
    }
}


/* process NAME, either issuer or subject */
static int GetName(DecodedCert* cert, int nameType)
{
    int    length;  /* length of all distinguished names */
    int    dummy;
    int    ret;
    char*  full;
    byte*  hash;
    word32 idx;
    #ifdef OPENSSL_EXTRA
        DecodedName* dName =
                  (nameType == ISSUER) ? &cert->issuerName : &cert->subjectName;
    #endif /* OPENSSL_EXTRA */

    WOLFSSL_MSG("Getting Cert Name");

    if (nameType == ISSUER) {
        full = cert->issuer;
        hash = cert->issuerHash;
    }
    else {
        full = cert->subject;
        hash = cert->subjectHash;
    }

    if (cert->source[cert->srcIdx] == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
            return ASN_PARSE_E;

        cert->srcIdx += length;
        WOLFSSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    idx = cert->srcIdx;
    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

#ifdef NO_SHA
    ret = wc_Sha256Hash(&cert->source[idx], length + cert->srcIdx - idx, hash);
#else
    ret = wc_ShaHash(&cert->source[idx], length + cert->srcIdx - idx, hash);
#endif
    if (ret != 0)
        return ret;

    length += cert->srcIdx;
    idx = 0;

#ifdef HAVE_PKCS7
    /* store pointer to raw issuer */
    if (nameType == ISSUER) {
        cert->issuerRaw = &cert->source[cert->srcIdx];
        cert->issuerRawLen = length - cert->srcIdx;
    }
#endif
#ifndef IGNORE_NAME_CONSTRAINTS
    if (nameType == SUBJECT) {
        cert->subjectRaw = &cert->source[cert->srcIdx];
        cert->subjectRawLen = length - cert->srcIdx;
    }
#endif

    while (cert->srcIdx < (word32)length) {
        byte   b;
        byte   joint[2];
        byte   tooBig = FALSE;
        int    oidSz;

        if (GetSet(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0) {
            WOLFSSL_MSG("Cert name lacks set header, trying sequence");
        }

        if (GetSequence(cert->source, &cert->srcIdx, &dummy, cert->maxIdx) < 0)
            return ASN_PARSE_E;

        b = cert->source[cert->srcIdx++];
        if (b != ASN_OBJECT_ID)
            return ASN_OBJECT_ID_E;

        if (GetLength(cert->source, &cert->srcIdx, &oidSz, cert->maxIdx) < 0)
            return ASN_PARSE_E;

        XMEMCPY(joint, &cert->source[cert->srcIdx], sizeof(joint));

        /* v1 name types */
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            byte   id;
            byte   copy = FALSE;
            int    strLen;

            cert->srcIdx += 2;
            id = cert->source[cert->srcIdx++];
            b  = cert->source[cert->srcIdx++]; /* encoding */

            if (GetLength(cert->source, &cert->srcIdx, &strLen,
                          cert->maxIdx) < 0)
                return ASN_PARSE_E;

            if ( (strLen + 14) > (int)(ASN_NAME_MAX - idx)) {
                /* include biggest pre fix header too 4 = "/serialNumber=" */
                WOLFSSL_MSG("ASN Name too big, skipping");
                tooBig = TRUE;
            }

            if (id == ASN_COMMON_NAME) {
                if (nameType == SUBJECT) {
                    cert->subjectCN = (char *)&cert->source[cert->srcIdx];
                    cert->subjectCNLen = strLen;
                    cert->subjectCNEnc = b;
                }

                if (!tooBig) {
                    XMEMCPY(&full[idx], "/CN=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef OPENSSL_EXTRA
                    dName->cnIdx = cert->srcIdx;
                    dName->cnLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_SUR_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/SN=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef WOLFSSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectSN = (char*)&cert->source[cert->srcIdx];
                        cert->subjectSNLen = strLen;
                        cert->subjectSNEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->snIdx = cert->srcIdx;
                    dName->snLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_COUNTRY_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/C=", 3);
                    idx += 3;
                    copy = TRUE;
                }
                #ifdef WOLFSSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectC = (char*)&cert->source[cert->srcIdx];
                        cert->subjectCLen = strLen;
                        cert->subjectCEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->cIdx = cert->srcIdx;
                    dName->cLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_LOCALITY_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/L=", 3);
                    idx += 3;
                    copy = TRUE;
                }
                #ifdef WOLFSSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectL = (char*)&cert->source[cert->srcIdx];
                        cert->subjectLLen = strLen;
                        cert->subjectLEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->lIdx = cert->srcIdx;
                    dName->lLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_STATE_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/ST=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef WOLFSSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectST = (char*)&cert->source[cert->srcIdx];
                        cert->subjectSTLen = strLen;
                        cert->subjectSTEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->stIdx = cert->srcIdx;
                    dName->stLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_ORG_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/O=", 3);
                    idx += 3;
                    copy = TRUE;
                }
                #ifdef WOLFSSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectO = (char*)&cert->source[cert->srcIdx];
                        cert->subjectOLen = strLen;
                        cert->subjectOEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->oIdx = cert->srcIdx;
                    dName->oLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_ORGUNIT_NAME) {
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/OU=", 4);
                    idx += 4;
                    copy = TRUE;
                }
                #ifdef WOLFSSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectOU = (char*)&cert->source[cert->srcIdx];
                        cert->subjectOULen = strLen;
                        cert->subjectOUEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->ouIdx = cert->srcIdx;
                    dName->ouLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_SERIAL_NUMBER) {
                if (!tooBig) {
                   XMEMCPY(&full[idx], "/serialNumber=", 14);
                   idx += 14;
                   copy = TRUE;
                }
                #ifdef OPENSSL_EXTRA
                    dName->snIdx = cert->srcIdx;
                    dName->snLen = strLen;
                #endif /* OPENSSL_EXTRA */
            }

            if (copy && !tooBig) {
                XMEMCPY(&full[idx], &cert->source[cert->srcIdx], strLen);
                idx += strLen;
            }

            cert->srcIdx += strLen;
        }
        else {
            /* skip */
            byte email = FALSE;
            byte uid   = FALSE;
            int  adv;

            if (joint[0] == 0x2a && joint[1] == 0x86)  /* email id hdr */
                email = TRUE;

            if (joint[0] == 0x9  && joint[1] == 0x92)  /* uid id hdr */
                uid = TRUE;

            cert->srcIdx += oidSz + 1;

            if (GetLength(cert->source, &cert->srcIdx, &adv, cert->maxIdx) < 0)
                return ASN_PARSE_E;

            if (adv > (int)(ASN_NAME_MAX - idx)) {
                WOLFSSL_MSG("ASN name too big, skipping");
                tooBig = TRUE;
            }

            if (email) {
                if ( (14 + adv) > (int)(ASN_NAME_MAX - idx)) {
                    WOLFSSL_MSG("ASN name too big, skipping");
                    tooBig = TRUE;
                }
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/emailAddress=", 14);
                    idx += 14;
                }

                #ifdef WOLFSSL_CERT_GEN
                    if (nameType == SUBJECT) {
                        cert->subjectEmail = (char*)&cert->source[cert->srcIdx];
                        cert->subjectEmailLen = adv;
                    }
                #endif /* WOLFSSL_CERT_GEN */
                #ifdef OPENSSL_EXTRA
                    dName->emailIdx = cert->srcIdx;
                    dName->emailLen = adv;
                #endif /* OPENSSL_EXTRA */
                #ifndef IGNORE_NAME_CONSTRAINTS
                    {
                        DNS_entry* emailName = NULL;

                        emailName = (DNS_entry*)XMALLOC(sizeof(DNS_entry),
                                              cert->heap, DYNAMIC_TYPE_ALTNAME);
                        if (emailName == NULL) {
                            WOLFSSL_MSG("\tOut of Memory");
                            return MEMORY_E;
                        }
                        emailName->name = (char*)XMALLOC(adv + 1,
                                              cert->heap, DYNAMIC_TYPE_ALTNAME);
                        if (emailName->name == NULL) {
                            WOLFSSL_MSG("\tOut of Memory");
                            XFREE(emailName, cert->heap, DYNAMIC_TYPE_ALTNAME);
                            return MEMORY_E;
                        }
                        XMEMCPY(emailName->name,
                                              &cert->source[cert->srcIdx], adv);
                        emailName->name[adv] = 0;

                        emailName->next = cert->altEmailNames;
                        cert->altEmailNames = emailName;
                    }
                #endif /* IGNORE_NAME_CONSTRAINTS */
                if (!tooBig) {
                    XMEMCPY(&full[idx], &cert->source[cert->srcIdx], adv);
                    idx += adv;
                }
            }

            if (uid) {
                if ( (5 + adv) > (int)(ASN_NAME_MAX - idx)) {
                    WOLFSSL_MSG("ASN name too big, skipping");
                    tooBig = TRUE;
                }
                if (!tooBig) {
                    XMEMCPY(&full[idx], "/UID=", 5);
                    idx += 5;

                    XMEMCPY(&full[idx], &cert->source[cert->srcIdx], adv);
                    idx += adv;
                }
                #ifdef OPENSSL_EXTRA
                    dName->uidIdx = cert->srcIdx;
                    dName->uidLen = adv;
                #endif /* OPENSSL_EXTRA */
            }

            cert->srcIdx += adv;
        }
    }
    full[idx++] = 0;

    #ifdef OPENSSL_EXTRA
    {
        int totalLen = 0;

        if (dName->cnLen != 0)
            totalLen += dName->cnLen + 4;
        if (dName->snLen != 0)
            totalLen += dName->snLen + 4;
        if (dName->cLen != 0)
            totalLen += dName->cLen + 3;
        if (dName->lLen != 0)
            totalLen += dName->lLen + 3;
        if (dName->stLen != 0)
            totalLen += dName->stLen + 4;
        if (dName->oLen != 0)
            totalLen += dName->oLen + 3;
        if (dName->ouLen != 0)
            totalLen += dName->ouLen + 4;
        if (dName->emailLen != 0)
            totalLen += dName->emailLen + 14;
        if (dName->uidLen != 0)
            totalLen += dName->uidLen + 5;
        if (dName->serialLen != 0)
            totalLen += dName->serialLen + 14;

        dName->fullName = (char*)XMALLOC(totalLen + 1, cert->heap,
                                                             DYNAMIC_TYPE_X509);
        if (dName->fullName != NULL) {
            idx = 0;

            if (dName->cnLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/CN=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->cnIdx], dName->cnLen);
                dName->cnIdx = idx;
                idx += dName->cnLen;
            }
            if (dName->snLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/SN=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->snIdx], dName->snLen);
                dName->snIdx = idx;
                idx += dName->snLen;
            }
            if (dName->cLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/C=", 3);
                idx += 3;
                XMEMCPY(&dName->fullName[idx],
                                       &cert->source[dName->cIdx], dName->cLen);
                dName->cIdx = idx;
                idx += dName->cLen;
            }
            if (dName->lLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/L=", 3);
                idx += 3;
                XMEMCPY(&dName->fullName[idx],
                                       &cert->source[dName->lIdx], dName->lLen);
                dName->lIdx = idx;
                idx += dName->lLen;
            }
            if (dName->stLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/ST=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->stIdx], dName->stLen);
                dName->stIdx = idx;
                idx += dName->stLen;
            }
            if (dName->oLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/O=", 3);
                idx += 3;
                XMEMCPY(&dName->fullName[idx],
                                       &cert->source[dName->oIdx], dName->oLen);
                dName->oIdx = idx;
                idx += dName->oLen;
            }
            if (dName->ouLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/OU=", 4);
                idx += 4;
                XMEMCPY(&dName->fullName[idx],
                                     &cert->source[dName->ouIdx], dName->ouLen);
                dName->ouIdx = idx;
                idx += dName->ouLen;
            }
            if (dName->emailLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/emailAddress=", 14);
                idx += 14;
                XMEMCPY(&dName->fullName[idx],
                               &cert->source[dName->emailIdx], dName->emailLen);
                dName->emailIdx = idx;
                idx += dName->emailLen;
            }
            if (dName->uidLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/UID=", 5);
                idx += 5;
                XMEMCPY(&dName->fullName[idx],
                                   &cert->source[dName->uidIdx], dName->uidLen);
                dName->uidIdx = idx;
                idx += dName->uidLen;
            }
            if (dName->serialLen != 0) {
                dName->entryCount++;
                XMEMCPY(&dName->fullName[idx], "/serialNumber=", 14);
                idx += 14;
                XMEMCPY(&dName->fullName[idx],
                             &cert->source[dName->serialIdx], dName->serialLen);
                dName->serialIdx = idx;
                idx += dName->serialLen;
            }
            dName->fullName[idx] = '\0';
            dName->fullNameLen = totalLen;
        }
    }
    #endif /* OPENSSL_EXTRA */

    return 0;
}


#if !defined(NO_TIME_H) && defined(USE_WOLF_VALIDDATE)

/* to the second */
static int DateGreaterThan(const struct tm* a, const struct tm* b)
{
    if (a->tm_year > b->tm_year)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon > b->tm_mon)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
           a->tm_mday > b->tm_mday)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour > b->tm_hour)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min > b->tm_min)
        return 1;

    if (a->tm_year == b->tm_year && a->tm_mon == b->tm_mon &&
        a->tm_mday == b->tm_mday && a->tm_hour == b->tm_hour &&
        a->tm_min  == b->tm_min  && a->tm_sec > b->tm_sec)
        return 1;

    return 0; /* false */
}


static INLINE int DateLessThan(const struct tm* a, const struct tm* b)
{
    return DateGreaterThan(b,a);
}


#if defined(WOLFSSL_MYSQL_COMPATIBLE)
int GetTimeString(byte* date, int format, char* buf, int len)
{
    struct tm t;
    int idx = 0;

    if (!ExtractDate(date, format, &t, &idx)) {
        return 0;
    }

    if (date[idx] != 'Z') {
        WOLFSSL_MSG("UTCtime, not Zulu") ;
        return 0;
    }

    /* place month in buffer */
    buf[0] = '\0';
    switch(t.tm_mon) {
        case 0:  XSTRNCAT(buf, "Jan ", 4); break;
        case 1:  XSTRNCAT(buf, "Feb ", 4); break;
        case 2:  XSTRNCAT(buf, "Mar ", 4); break;
        case 3:  XSTRNCAT(buf, "Apr ", 4); break;
        case 4:  XSTRNCAT(buf, "May ", 4); break;
        case 5:  XSTRNCAT(buf, "Jun ", 4); break;
        case 6:  XSTRNCAT(buf, "Jul ", 4); break;
        case 7:  XSTRNCAT(buf, "Aug ", 4); break;
        case 8:  XSTRNCAT(buf, "Sep ", 4); break;
        case 9:  XSTRNCAT(buf, "Oct ", 4); break;
        case 10: XSTRNCAT(buf, "Nov ", 4); break;
        case 11: XSTRNCAT(buf, "Dec ", 4); break;
        default:
            return 0;

    }
    idx = 4; /* use idx now for char buffer */
    buf[idx] = ' ';

    XSNPRINTF(buf + idx, len - idx, "%2d %02d:%02d:%02d %d GMT",
              t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, t.tm_year + 1900);

    return 1;
}
#endif /* MYSQL compatibility */

int ExtractDate(const unsigned char* date, unsigned char format,
                                                  struct tm* certTime, int* idx)
{
    XMEMSET(certTime, 0, sizeof(struct tm));

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            certTime->tm_year = 1900;
        else
            certTime->tm_year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        certTime->tm_year += btoi(date[*idx]) * 1000; *idx = *idx + 1;
        certTime->tm_year += btoi(date[*idx]) * 100;  *idx = *idx + 1;
    }

    /* adjust tm_year, tm_mon */
    GetTime((int*)&certTime->tm_year, date, idx); certTime->tm_year -= 1900;
    GetTime((int*)&certTime->tm_mon,  date, idx); certTime->tm_mon  -= 1;
    GetTime((int*)&certTime->tm_mday, date, idx);
    GetTime((int*)&certTime->tm_hour, date, idx);
    GetTime((int*)&certTime->tm_min,  date, idx);
    GetTime((int*)&certTime->tm_sec,  date, idx);

    return 1;
}


/* like atoi but only use first byte */
/* Make sure before and after dates are valid */
int ValidateDate(const byte* date, byte format, int dateType)
{
    time_t ltime;
    struct tm  certTime;
    struct tm* localTime;
    struct tm* tmpTime = NULL;
    int    i = 0;
    int    timeDiff = 0 ;
    int    diffHH = 0 ; int diffMM = 0 ;
    int    diffSign = 0 ;

#if defined(NEED_TMP_TIME)
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    (void)tmpTime;
#endif

    ltime = XTIME(0);
    if (!ExtractDate(date, format, &certTime, &i)) {
        WOLFSSL_MSG("Error extracting the date");
        return 0;
    }

    if ((date[i] == '+') || (date[i] == '-')) {
        WOLFSSL_MSG("Using time differential, not Zulu") ;
        diffSign = date[i++] == '+' ? 1 : -1 ;
        GetTime(&diffHH, date, &i);
        GetTime(&diffMM, date, &i);
        timeDiff = diffSign * (diffHH*60 + diffMM) * 60 ;
    } else if (date[i] != 'Z') {
        WOLFSSL_MSG("UTCtime, niether Zulu or time differential") ;
        return 0;
    }

    ltime -= (time_t)timeDiff ;
    localTime = XGMTIME(&ltime, tmpTime);

    if (localTime == NULL) {
        WOLFSSL_MSG("XGMTIME failed");
        return 0;
    }

    if (dateType == BEFORE) {
        if (DateLessThan(localTime, &certTime))
            return 0;
    }
    else
        if (DateGreaterThan(localTime, &certTime))
            return 0;

    return 1;
}
#endif /* !NO_TIME_H && USE_WOLF_VALIDDATE */

int wc_GetTime(void* timePtr, word32 timeSize)
{
    time_t* ltime = (time_t*)timePtr;

    if (timePtr == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((word32)sizeof(time_t) > timeSize) {
        return BUFFER_E;
    }

    *ltime = XTIME(0);

    return 0;
}

static int GetDate(DecodedCert* cert, int dateType)
{
    int    length;
    byte   date[MAX_DATE_SIZE];
    byte   b;
    word32 startIdx = 0;

    if (dateType == BEFORE)
        cert->beforeDate = &cert->source[cert->srcIdx];
    else
        cert->afterDate = &cert->source[cert->srcIdx];
    startIdx = cert->srcIdx;

    b = cert->source[cert->srcIdx++];
    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    XMEMCPY(date, &cert->source[cert->srcIdx], length);
    cert->srcIdx += length;

    if (dateType == BEFORE)
        cert->beforeDateLen = cert->srcIdx - startIdx;
    else
        cert->afterDateLen  = cert->srcIdx - startIdx;

    if (!XVALIDATE_DATE(date, b, dateType)) {
        if (dateType == BEFORE)
            return ASN_BEFORE_DATE_E;
        else
            return ASN_AFTER_DATE_E;
    }

    return 0;
}


static int GetValidity(DecodedCert* cert, int verify)
{
    int length;
    int badDate = 0;

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetDate(cert, BEFORE) < 0 && verify)
        badDate = ASN_BEFORE_DATE_E;           /* continue parsing */

    if (GetDate(cert, AFTER) < 0 && verify)
        return ASN_AFTER_DATE_E;

    if (badDate != 0)
        return badDate;

    return 0;
}


int DecodeToKey(DecodedCert* cert, int verify)
{
    int badDate = 0;
    int ret;

    if ( (ret = GetCertHeader(cert)) < 0)
        return ret;

    WOLFSSL_MSG("Got Cert Header");

    if ( (ret = GetAlgoId(cert->source, &cert->srcIdx, &cert->signatureOID,
                          oidSigType, cert->maxIdx)) < 0)
        return ret;

    WOLFSSL_MSG("Got Algo ID");

    if ( (ret = GetName(cert, ISSUER)) < 0)
        return ret;

    if ( (ret = GetValidity(cert, verify)) < 0)
        badDate = ret;

    if ( (ret = GetName(cert, SUBJECT)) < 0)
        return ret;

    WOLFSSL_MSG("Got Subject Name");

    if ( (ret = GetKey(cert)) < 0)
        return ret;

    WOLFSSL_MSG("Got Key");

    if (badDate != 0)
        return badDate;

    return ret;
}


static int GetSignature(DecodedCert* cert)
{
    int    length;
    byte   b = cert->source[cert->srcIdx++];

    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->sigLength = length;

    b = cert->source[cert->srcIdx++];
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    cert->sigLength--;
    cert->signature = &cert->source[cert->srcIdx];
    cert->srcIdx += cert->sigLength;

    return 0;
}
#endif /* !NO_ASN_TIME */

static word32 SetDigest(const byte* digest, word32 digSz, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = (byte)digSz;
    XMEMCPY(&output[2], digest, digSz);

    return digSz + 2;
}


static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * WOLFSSL_BIT_SIZE))
            break;

    return i;
}


WOLFSSL_LOCAL word32 SetLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = (byte)length;
    else {
        output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);

        for (j = BytePrecision(length); j; --j) {
            output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}


WOLFSSL_LOCAL word32 SetSequence(word32 len, byte* output)
{
    output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}

WOLFSSL_LOCAL word32 SetOctetString(word32 len, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    return SetLength(len, output + 1) + 1;
}

/* Write a set header to output */
WOLFSSL_LOCAL word32 SetSet(word32 len, byte* output)
{
    output[0] = ASN_SET | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}

WOLFSSL_LOCAL word32 SetImplicit(byte tag, byte number, word32 len, byte* output)
{

    output[0] = ((tag == ASN_SEQUENCE || tag == ASN_SET) ? ASN_CONSTRUCTED : 0)
                    | ASN_CONTEXT_SPECIFIC | number;
    return SetLength(len, output + 1) + 1;
}

WOLFSSL_LOCAL word32 SetExplicit(byte number, word32 len, byte* output)
{
    output[0] = ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | number;
    return SetLength(len, output + 1) + 1;
}


#if defined(HAVE_ECC) && (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))

static int SetCurve(ecc_key* key, byte* output)
{
    int ret;
    int idx = 0;
    word32 oidSz = 0;

    /* validate key */
    if (key == NULL || key->dp == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_OID_ENCODING
    ret = EncodeObjectId(key->dp->oid, key->dp->oidSz, NULL, &oidSz);
    if (ret != 0) {
        return ret;
    }
#else
    oidSz = key->dp->oidSz;
#endif

    output[0] = ASN_OBJECT_ID;
    idx++;

    ret = SetLength(oidSz, output+idx);
    idx += ret;

#ifdef HAVE_OID_ENCODING
    ret = EncodeObjectId(key->dp->oid, key->dp->oidSz, output+idx, &oidSz);
    if (ret != 0) {
        return ret;
    }
#else
    XMEMCPY(output+idx, key->dp->oid, oidSz);
#endif
    idx += oidSz;

    return idx;
}

#endif /* HAVE_ECC && WOLFSSL_CERT_GEN */


static INLINE int IsSigAlgoECDSA(int algoOID)
{
    /* ECDSA sigAlgo must not have ASN1 NULL parameters */
    if (algoOID == CTC_SHAwECDSA || algoOID == CTC_SHA256wECDSA ||
        algoOID == CTC_SHA384wECDSA || algoOID == CTC_SHA512wECDSA) {
        return 1;
    }

    return 0;
}

WOLFSSL_LOCAL word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz)
{
    word32 tagSz, idSz, seqSz, algoSz = 0;
    const  byte* algoName = 0;
    byte   ID_Length[MAX_LENGTH_SZ];
    byte   seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */

    tagSz = (type == oidHashType ||
             (type == oidSigType && !IsSigAlgoECDSA(algoOID)) ||
             (type == oidKeyType && algoOID == RSAk)) ? 2 : 0;

    algoName = OidFromId(algoOID, type, &algoSz);

    if (algoName == NULL) {
        WOLFSSL_MSG("Unknown Algorithm");
        return 0;
    }

    idSz  = SetLength(algoSz, ID_Length);
    seqSz = SetSequence(idSz + algoSz + 1 + tagSz + curveSz, seqArray);
                 /* +1 for object id, curveID of curveSz follows for ecc */
    seqArray[seqSz++] = ASN_OBJECT_ID;

    XMEMCPY(output, seqArray, seqSz);
    XMEMCPY(output + seqSz, ID_Length, idSz);
    XMEMCPY(output + seqSz + idSz, algoName, algoSz);
    if (tagSz == 2) {
        output[seqSz + idSz + algoSz] = ASN_TAG_NULL;
        output[seqSz + idSz + algoSz + 1] = 0;
    }

    return seqSz + idSz + algoSz + tagSz;

}


word32 wc_EncodeSignature(byte* out, const byte* digest, word32 digSz,
                          int hashOID)
{
    byte digArray[MAX_ENCODED_DIG_SZ];
    byte algoArray[MAX_ALGO_SZ];
    byte seqArray[MAX_SEQ_SZ];
    word32 encDigSz, algoSz, seqSz;

    encDigSz = SetDigest(digest, digSz, digArray);
    algoSz   = SetAlgoID(hashOID, algoArray, oidHashType, 0);
    seqSz    = SetSequence(encDigSz + algoSz, seqArray);

    XMEMCPY(out, seqArray, seqSz);
    XMEMCPY(out + seqSz, algoArray, algoSz);
    XMEMCPY(out + seqSz + algoSz, digArray, encDigSz);

    return encDigSz + algoSz + seqSz;
}


int wc_GetCTC_HashOID(int type)
{
    switch (type) {
#ifdef WOLFSSL_MD2
        case MD2:
            return MD2h;
#endif
#ifndef NO_MD5
        case MD5:
            return MD5h;
#endif
#ifndef NO_SHA
        case SHA:
            return SHAh;
#endif
#ifndef NO_SHA256
        case SHA256:
            return SHA256h;
#endif
#ifdef WOLFSSL_SHA384
        case SHA384:
            return SHA384h;
#endif
#ifdef WOLFSSL_SHA512
        case SHA512:
            return SHA512h;
#endif
        default:
            return 0;
    };
}

#ifndef NO_ASN_TIME
/* return true (1) or false (0) for Confirmation */
static int ConfirmSignature(const byte* buf, word32 bufSz,
    const byte* key, word32 keySz, word32 keyOID,
    const byte* sig, word32 sigSz, word32 sigOID,
    void* heap)
{
    int  typeH = 0, digestSz = 0, ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* digest;
#else
    byte digest[WC_MAX_DIGEST_SIZE];
#endif

#ifdef WOLFSSL_SMALL_STACK
    digest = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (digest == NULL)
        return 0; /* not confirmed */
#endif

    (void)key;
    (void)keySz;
    (void)sig;
    (void)sigSz;
    (void)heap;

    switch (sigOID) {
    #ifndef NO_MD5
        case CTC_MD5wRSA:
        if (wc_Md5Hash(buf, bufSz, digest) == 0) {
            typeH    = MD5h;
            digestSz = MD5_DIGEST_SIZE;
        }
        break;
    #endif
    #if defined(WOLFSSL_MD2)
        case CTC_MD2wRSA:
        if (wc_Md2Hash(buf, bufSz, digest) == 0) {
            typeH    = MD2h;
            digestSz = MD2_DIGEST_SIZE;
        }
        break;
    #endif
    #ifndef NO_SHA
        case CTC_SHAwRSA:
        case CTC_SHAwDSA:
        case CTC_SHAwECDSA:
        if (wc_ShaHash(buf, bufSz, digest) == 0) {
            typeH    = SHAh;
            digestSz = SHA_DIGEST_SIZE;
        }
        break;
    #endif
    #ifndef NO_SHA256
        case CTC_SHA256wRSA:
        case CTC_SHA256wECDSA:
        if (wc_Sha256Hash(buf, bufSz, digest) == 0) {
            typeH    = SHA256h;
            digestSz = SHA256_DIGEST_SIZE;
        }
        break;
    #endif
    #ifdef WOLFSSL_SHA512
        case CTC_SHA512wRSA:
        case CTC_SHA512wECDSA:
        if (wc_Sha512Hash(buf, bufSz, digest) == 0) {
            typeH    = SHA512h;
            digestSz = SHA512_DIGEST_SIZE;
        }
        break;
    #endif
    #ifdef WOLFSSL_SHA384
        case CTC_SHA384wRSA:
        case CTC_SHA384wECDSA:
        if (wc_Sha384Hash(buf, bufSz, digest) == 0) {
            typeH    = SHA384h;
            digestSz = SHA384_DIGEST_SIZE;
        }
        break;
    #endif
        default:
            WOLFSSL_MSG("Verify Signature has unsupported type");
    }

    if (typeH == 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return 0; /* not confirmed */
    }

    switch (keyOID) {
    #ifndef NO_RSA
        case RSAk:
        {
            word32 idx = 0;
            int    encodedSigSz, verifySz;
            byte*  out;
#ifdef WOLFSSL_SMALL_STACK
            RsaKey* pubKey;
            byte* plain;
            byte* encodedSig;
#else
            RsaKey pubKey[1];
            byte plain[MAX_ENCODED_SIG_SZ];
            byte encodedSig[MAX_ENCODED_SIG_SZ];
#endif

#ifdef WOLFSSL_SMALL_STACK
            pubKey = (RsaKey*)XMALLOC(sizeof(RsaKey), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            plain = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);

            if (pubKey == NULL || plain == NULL || encodedSig == NULL) {
                WOLFSSL_MSG("Failed to allocate memory at ConfirmSignature");

                if (pubKey)
                    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (plain)
                    XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (encodedSig)
                    XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);

                break; /* not confirmed */
            }
#endif
            if (wc_InitRsaKey(pubKey, heap) != 0) {
                WOLFSSL_MSG("InitRsaKey failed");
            }
            else if (sigSz > MAX_ENCODED_SIG_SZ) {
                WOLFSSL_MSG("Verify Signature is too big");
            }
            else if (wc_RsaPublicKeyDecode(key, &idx, pubKey, keySz) < 0) {
                WOLFSSL_MSG("ASN Key decode error RSA");
            }
            else {
                XMEMCPY(plain, sig, sigSz);

                ret = 0;
                do {
                #if defined(WOLFSSL_ASYNC_CRYPT)
                    ret = wc_RsaAsyncWait(ret, pubKey);
                #endif
                    if (ret >= 0) {
                        ret = wc_RsaSSL_VerifyInline(plain, sigSz, &out,
                                                                    pubKey);
                    }
                } while (ret == WC_PENDING_E);

                if (ret < 0) {
                    WOLFSSL_MSG("Rsa SSL verify error");
                }
                else {
                    verifySz = ret;
                    /* make sure we're right justified */
                    encodedSigSz =
                        wc_EncodeSignature(encodedSig, digest, digestSz, typeH);
                    if (encodedSigSz != verifySz ||
                                XMEMCMP(out, encodedSig, encodedSigSz) != 0) {
                        WOLFSSL_MSG("Rsa SSL verify match encode error");
                    }
                    else
                        ret = 1; /* match */

                    #ifdef WOLFSSL_DEBUG_ENCODING
                    {
                        int x;

                        printf("wolfssl encodedSig:\n");

                        for (x = 0; x < encodedSigSz; x++) {
                            printf("%02x ", encodedSig[x]);
                            if ( (x % 16) == 15)
                                printf("\n");
                        }

                        printf("\n");
                        printf("actual digest:\n");

                        for (x = 0; x < verifySz; x++) {
                            printf("%02x ", out[x]);
                            if ( (x % 16) == 15)
                                printf("\n");
                        }

                        printf("\n");
                    }
                    #endif /* WOLFSSL_DEBUG_ENCODING */

                }

            }

            wc_FreeRsaKey(pubKey);

#ifdef WOLFSSL_SMALL_STACK
            XFREE(pubKey,     NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(plain,      NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            break;
        }

    #endif /* NO_RSA */
    #ifdef HAVE_ECC
        case ECDSAk:
        {
            int verify = 0;
#ifdef WOLFSSL_SMALL_STACK
            ecc_key* pubKey;
#else
            ecc_key pubKey[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
            pubKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (pubKey == NULL) {
                WOLFSSL_MSG("Failed to allocate pubKey");
                break; /* not confirmed */
            }
#endif

            if (wc_ecc_init(pubKey) < 0) {
                WOLFSSL_MSG("Failed to initialize key");
                break; /* not confirmed */
            }
            if (wc_ecc_import_x963(key, keySz, pubKey) < 0) {
                WOLFSSL_MSG("ASN Key import error ECC");
            }
            else {
                if (wc_ecc_verify_hash(sig, sigSz, digest, digestSz, &verify,
                                                                pubKey) != 0) {
                    WOLFSSL_MSG("ECC verify hash error");
                }
                else if (1 != verify) {
                    WOLFSSL_MSG("ECC Verify didn't match");
                } else
                    ret = 1; /* match */

            }
            wc_ecc_free(pubKey);

#ifdef WOLFSSL_SMALL_STACK
            XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            break;
        }
    #endif /* HAVE_ECC */
        default:
            WOLFSSL_MSG("Verify Key type unknown");
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


#ifndef IGNORE_NAME_CONSTRAINTS

static int MatchBaseName(int type, const char* name, int nameSz,
                         const char* base, int baseSz)
{
    if (base == NULL || baseSz <= 0 || name == NULL || nameSz <= 0 ||
            name[0] == '.' || nameSz < baseSz ||
            (type != ASN_RFC822_TYPE && type != ASN_DNS_TYPE))
        return 0;

    /* If an email type, handle special cases where the base is only
     * a domain, or is an email address itself. */
    if (type == ASN_RFC822_TYPE) {
        const char* p = NULL;
        int count = 0;

        if (base[0] != '.') {
            p = base;
            count = 0;

            /* find the '@' in the base */
            while (*p != '@' && count < baseSz) {
                count++;
                p++;
            }

            /* No '@' in base, reset p to NULL */
            if (count >= baseSz)
                p = NULL;
        }

        if (p == NULL) {
            /* Base isn't an email address, it is a domain name,
             * wind the name forward one character past its '@'. */
            p = name;
            count = 0;
            while (*p != '@' && count < baseSz) {
                count++;
                p++;
            }

            if (count < baseSz && *p == '@') {
                name = p + 1;
                nameSz -= count + 1;
            }
        }
    }

    if ((type == ASN_DNS_TYPE || type == ASN_RFC822_TYPE) && base[0] == '.') {
        int szAdjust = nameSz - baseSz;
        name += szAdjust;
        nameSz -= szAdjust;
    }

    while (nameSz > 0) {
        if (XTOLOWER((unsigned char)*name++) !=
                                               XTOLOWER((unsigned char)*base++))
            return 0;
        nameSz--;
    }

    return 1;
}


static int ConfirmNameConstraints(Signer* signer, DecodedCert* cert)
{
    if (signer == NULL || cert == NULL)
        return 0;

    /* Check against the excluded list */
    if (signer->excludedNames) {
        Base_entry* base = signer->excludedNames;

        while (base != NULL) {
            if (base->type == ASN_DNS_TYPE) {
                DNS_entry* name = cert->altNames;
                while (name != NULL) {
                    if (MatchBaseName(ASN_DNS_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz))
                        return 0;
                    name = name->next;
                }
            }
            else if (base->type == ASN_RFC822_TYPE) {
                DNS_entry* name = cert->altEmailNames;
                while (name != NULL) {
                    if (MatchBaseName(ASN_RFC822_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz))
                        return 0;

                    name = name->next;
                }
            }
            else if (base->type == ASN_DIR_TYPE) {
                if (cert->subjectRawLen == base->nameSz &&
                    XMEMCMP(cert->subjectRaw, base->name, base->nameSz) == 0) {

                    return 0;
                }
            }
            base = base->next;
        }
    }

    /* Check against the permitted list */
    if (signer->permittedNames != NULL) {
        int needDns = 0;
        int matchDns = 0;
        int needEmail = 0;
        int matchEmail = 0;
        int needDir = 0;
        int matchDir = 0;
        Base_entry* base = signer->permittedNames;

        while (base != NULL) {
            if (base->type == ASN_DNS_TYPE) {
                DNS_entry* name = cert->altNames;

                if (name != NULL)
                    needDns = 1;

                while (name != NULL) {
                    matchDns = MatchBaseName(ASN_DNS_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz);
                    name = name->next;
                }
            }
            else if (base->type == ASN_RFC822_TYPE) {
                DNS_entry* name = cert->altEmailNames;

                if (name != NULL)
                    needEmail = 1;

                while (name != NULL) {
                    matchEmail = MatchBaseName(ASN_DNS_TYPE,
                                          name->name, (int)XSTRLEN(name->name),
                                          base->name, base->nameSz);
                    name = name->next;
                }
            }
            else if (base->type == ASN_DIR_TYPE) {
                needDir = 1;
                if (cert->subjectRaw != NULL &&
                    cert->subjectRawLen == base->nameSz &&
                    XMEMCMP(cert->subjectRaw, base->name, base->nameSz) == 0) {

                    matchDir = 1;
                }
            }
            base = base->next;
        }

        if ((needDns && !matchDns) || (needEmail && !matchEmail) ||
            (needDir && !matchDir)) {

            return 0;
        }
    }

    return 1;
}

#endif /* IGNORE_NAME_CONSTRAINTS */


static int DecodeAltNames(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER("DecodeAltNames");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tBad Sequence");
        return ASN_PARSE_E;
    }

    cert->weOwnAltNames = 1;

    while (length > 0) {
        byte       b = input[idx++];

        length--;

        /* Save DNS Type names in the altNames list. */
        /* Save Other Type names in the cert's OidMap */
        if (b == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE)) {
            DNS_entry* dnsEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            dnsEntry = (DNS_entry*)XMALLOC(sizeof(DNS_entry), cert->heap,
                                        DYNAMIC_TYPE_ALTNAME);
            if (dnsEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return ASN_PARSE_E;
            }

            dnsEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (dnsEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return ASN_PARSE_E;
            }

            XMEMCPY(dnsEntry->name, &input[idx], strLen);
            dnsEntry->name[strLen] = '\0';

            dnsEntry->next = cert->altNames;
            cert->altNames = dnsEntry;

            length -= strLen;
            idx    += strLen;
        }
#ifndef IGNORE_NAME_CONSTRAINTS
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE)) {
            DNS_entry* emailEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);

            emailEntry = (DNS_entry*)XMALLOC(sizeof(DNS_entry), cert->heap,
                                        DYNAMIC_TYPE_ALTNAME);
            if (emailEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return ASN_PARSE_E;
            }

            emailEntry->name = (char*)XMALLOC(strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (emailEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(emailEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return ASN_PARSE_E;
            }

            XMEMCPY(emailEntry->name, &input[idx], strLen);
            emailEntry->name[strLen] = '\0';

            emailEntry->next = cert->altEmailNames;
            cert->altEmailNames = emailEntry;

            length -= strLen;
            idx    += strLen;
        }
#endif /* IGNORE_NAME_CONSTRAINTS */
#ifdef WOLFSSL_SEP
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_OTHER_TYPE))
        {
            int strLen;
            word32 lenStartIdx = idx;
            word32 oid = 0;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: other name length");
                return ASN_PARSE_E;
            }
            /* Consume the rest of this sequence. */
            length -= (strLen + idx - lenStartIdx);

            if (GetObjectId(input, &idx, &oid, oidCertAltNameType, sz) < 0) {
                WOLFSSL_MSG("\tbad OID");
                return ASN_PARSE_E;
            }

            if (oid != HW_NAME_OID) {
                WOLFSSL_MSG("\tincorrect OID");
                return ASN_PARSE_E;
            }

            if (input[idx++] != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
                WOLFSSL_MSG("\twrong type");
                return ASN_PARSE_E;
            }

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str len");
                return ASN_PARSE_E;
            }

            if (GetSequence(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tBad Sequence");
                return ASN_PARSE_E;
            }

            if (input[idx++] != ASN_OBJECT_ID) {
                WOLFSSL_MSG("\texpected OID");
                return ASN_PARSE_E;
            }

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfailed: str len");
                return ASN_PARSE_E;
            }

            cert->hwType = (byte*)XMALLOC(strLen, cert->heap,
                                          DYNAMIC_TYPE_X509_EXT);
            if (cert->hwType == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            XMEMCPY(cert->hwType, &input[idx], strLen);
            cert->hwTypeSz = strLen;
            idx += strLen;

            if (input[idx++] != ASN_OCTET_STRING) {
                WOLFSSL_MSG("\texpected Octet String");
                return ASN_PARSE_E;
            }

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfailed: str len");
                return ASN_PARSE_E;
            }

            cert->hwSerialNum = (byte*)XMALLOC(strLen + 1, cert->heap,
                                               DYNAMIC_TYPE_X509_EXT);
            if (cert->hwSerialNum == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            XMEMCPY(cert->hwSerialNum, &input[idx], strLen);
            cert->hwSerialNum[strLen] = '\0';
            cert->hwSerialNumSz = strLen;
            idx += strLen;
        }
#endif /* WOLFSSL_SEP */
        else {
            int strLen;
            word32 lenStartIdx = idx;

            WOLFSSL_MSG("\tUnsupported name type, skipping");

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: unsupported name length");
                return ASN_PARSE_E;
            }
            length -= (strLen + idx - lenStartIdx);
            idx += strLen;
        }
    }
    return 0;
}


static int DecodeBasicCaConstraint(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER("DecodeBasicCaConstraint");
    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: bad SEQUENCE");
        return ASN_PARSE_E;
    }

    if (length == 0)
        return 0;

    /* If the basic ca constraint is false, this extension may be named, but
     * left empty. So, if the length is 0, just return. */

    if (input[idx++] != ASN_BOOLEAN)
    {
        WOLFSSL_MSG("\tfail: constraint not BOOLEAN");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0)
    {
        WOLFSSL_MSG("\tfail: length");
        return ASN_PARSE_E;
    }

    if (input[idx++])
        cert->isCA = 1;

    /* If there isn't any more data, return. */
    if (idx >= (word32)sz)
        return 0;

    /* Anything left should be the optional pathlength */
    if (input[idx++] != ASN_INTEGER) {
        WOLFSSL_MSG("\tfail: pathlen not INTEGER");
        return ASN_PARSE_E;
    }

    if (input[idx++] != 1) {
        WOLFSSL_MSG("\tfail: pathlen too long");
        return ASN_PATHLEN_SIZE_E;
    }

    cert->pathLength = input[idx];
    cert->pathLengthSet = 1;

    return 0;
}


#define CRLDP_FULL_NAME 0
    /* From RFC3280 SS4.2.1.14, Distribution Point Name*/
#define GENERALNAME_URI 6
    /* From RFC3280 SS4.2.1.7, GeneralName */

static int DecodeCrlDist(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER("DecodeCrlDist");

    /* Unwrap the list of Distribution Points*/
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* Unwrap a single Distribution Point */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* The Distribution Point has three explicit optional members
     *  First check for a DistributionPointName
     */
    if (input[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (input[idx] ==
                    (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | CRLDP_FULL_NAME))
        {
            idx++;
            if (GetLength(input, &idx, &length, sz) < 0)
                return ASN_PARSE_E;

            if (input[idx] == (ASN_CONTEXT_SPECIFIC | GENERALNAME_URI))
            {
                idx++;
                if (GetLength(input, &idx, &length, sz) < 0)
                    return ASN_PARSE_E;

                cert->extCrlInfoSz = length;
                cert->extCrlInfo = input + idx;
                idx += length;
            }
            else
                /* This isn't a URI, skip it. */
                idx += length;
        }
        else
            /* This isn't a FULLNAME, skip it. */
            idx += length;
    }

    /* Check for reasonFlags */
    if (idx < (word32)sz &&
        input[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    /* Check for cRLIssuer */
    if (idx < (word32)sz &&
        input[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 2))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    if (idx < (word32)sz)
    {
        WOLFSSL_MSG("\tThere are more CRL Distribution Point records, "
                   "but we only use the first one.");
    }

    return 0;
}


static int DecodeAuthInfo(byte* input, int sz, DecodedCert* cert)
/*
 *  Read the first of the Authority Information Access records. If there are
 *  any issues, return without saving the record.
 */
{
    word32 idx = 0;
    int length = 0;
    byte b;
    word32 oid;

    WOLFSSL_ENTER("DecodeAuthInfo");

    /* Unwrap the list of AIAs */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    while (idx < (word32)sz) {
        /* Unwrap a single AIA */
        if (GetSequence(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        oid = 0;
        if (GetObjectId(input, &idx, &oid, oidCertAuthInfoType, sz) < 0)
            return ASN_PARSE_E;

        /* Only supporting URIs right now. */
        b = input[idx++];
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (b == (ASN_CONTEXT_SPECIFIC | GENERALNAME_URI) &&
            oid == AIA_OCSP_OID)
        {
            cert->extAuthInfoSz = length;
            cert->extAuthInfo = input + idx;
            break;
        }
        idx += length;
    }

    return 0;
}


static int DecodeAuthKeyId(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0, ret = 0;

    WOLFSSL_ENTER("DecodeAuthKeyId");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE\n");
        return ASN_PARSE_E;
    }

    if (input[idx++] != (ASN_CONTEXT_SPECIFIC | 0)) {
        WOLFSSL_MSG("\tinfo: OPTIONAL item 0, not available\n");
        return 0;
    }

    if (GetLength(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: extension data length");
        return ASN_PARSE_E;
    }

    #ifdef OPENSSL_EXTRA
        cert->extAuthKeyIdSrc = &input[idx];
        cert->extAuthKeyIdSz = length;
    #endif /* OPENSSL_EXTRA */

    if (length == KEYID_SIZE) {
        XMEMCPY(cert->extAuthKeyId, input + idx, length);
    }
    else {
    #ifdef NO_SHA
        ret = wc_Sha256Hash(input + idx, length, cert->extAuthKeyId);
    #else
        ret = wc_ShaHash(input + idx, length, cert->extAuthKeyId);
    #endif
    }

    return ret;
}


static int DecodeSubjKeyId(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0, ret = 0;

    WOLFSSL_ENTER("DecodeSubjKeyId");

    if (input[idx++] != ASN_OCTET_STRING) {
        WOLFSSL_MSG("\tfail: should be an OCTET STRING");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: extension data length");
        return ASN_PARSE_E;
    }

    #ifdef OPENSSL_EXTRA
        cert->extSubjKeyIdSrc = &input[idx];
        cert->extSubjKeyIdSz = length;
    #endif /* OPENSSL_EXTRA */

    if (length == SIGNER_DIGEST_SIZE) {
        XMEMCPY(cert->extSubjKeyId, input + idx, length);
    }
    else {
    #ifdef NO_SHA
        ret = wc_Sha256Hash(input + idx, length, cert->extSubjKeyId);
    #else
        ret = wc_ShaHash(input + idx, length, cert->extSubjKeyId);
    #endif
    }

    return ret;
}


static int DecodeKeyUsage(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length;
    WOLFSSL_ENTER("DecodeKeyUsage");

    if (input[idx++] != ASN_BIT_STRING) {
        WOLFSSL_MSG("\tfail: key usage expected bit string");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: key usage bad length");
        return ASN_PARSE_E;
    }

    /* pass the unusedBits value */
    idx++; length--;

    cert->extKeyUsage = (word16)(input[idx]);
    if (length == 2)
        cert->extKeyUsage |= (word16)(input[idx+1] << 8);

    return 0;
}


static int DecodeExtKeyUsage(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0, oid;
    int length;

    WOLFSSL_ENTER("DecodeExtKeyUsage");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    #ifdef OPENSSL_EXTRA
        cert->extExtKeyUsageSrc = input + idx;
        cert->extExtKeyUsageSz = length;
    #endif

    while (idx < (word32)sz) {
        if (GetObjectId(input, &idx, &oid, oidCertKeyUseType, sz) < 0)
            return ASN_PARSE_E;

        switch (oid) {
            case EKU_ANY_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_ANY;
                break;
            case EKU_SERVER_AUTH_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_SERVER_AUTH;
                break;
            case EKU_CLIENT_AUTH_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_CLIENT_AUTH;
                break;
            case EKU_OCSP_SIGN_OID:
                cert->extExtKeyUsage |= EXTKEYUSE_OCSP_SIGN;
                break;
        }

        #ifdef OPENSSL_EXTRA
            cert->extExtKeyUsageCount++;
        #endif
    }

    return 0;
}


#ifndef IGNORE_NAME_CONSTRAINTS
static int DecodeSubtree(byte* input, int sz, Base_entry** head, void* heap)
{
    word32 idx = 0;

    (void)heap;

    while (idx < (word32)sz) {
        int seqLength, strLength;
        word32 nameIdx;
        byte b;

        if (GetSequence(input, &idx, &seqLength, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        nameIdx = idx;
        b = input[nameIdx++];
        if (GetLength(input, &nameIdx, &strLength, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        if (b == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE) ||
            b == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE) ||
            b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE)) {

            Base_entry* entry = (Base_entry*)XMALLOC(sizeof(Base_entry),
                                                    heap, DYNAMIC_TYPE_ALTNAME);

            if (entry == NULL) {
                WOLFSSL_MSG("allocate error");
                return MEMORY_E;
            }

            entry->name = (char*)XMALLOC(strLength, heap, DYNAMIC_TYPE_ALTNAME);
            if (entry->name == NULL) {
                WOLFSSL_MSG("allocate error");
                XFREE(entry, heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }

            XMEMCPY(entry->name, &input[nameIdx], strLength);
            entry->nameSz = strLength;
            entry->type = b & 0x0F;

            entry->next = *head;
            *head = entry;
        }

        idx += seqLength;
    }

    return 0;
}


static int DecodeNameConstraints(byte* input, int sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER("DecodeNameConstraints");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    while (idx < (word32)sz) {
        byte b = input[idx++];
        Base_entry** subtree = NULL;

        if (GetLength(input, &idx, &length, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
            subtree = &cert->permittedNames;
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
            subtree = &cert->excludedNames;
        else {
            WOLFSSL_MSG("\tinvalid subtree");
            return ASN_PARSE_E;
        }

        DecodeSubtree(input + idx, length, subtree, cert->heap);

        idx += length;
    }

    return 0;
}
#endif /* IGNORE_NAME_CONSTRAINTS */
#endif /* NO_ASN_TIME */

#if defined(WOLFSSL_CERT_EXT) && !defined(WOLFSSL_SEP)

static int Word32ToString(char* d, word32 number)
{
    int i = 0;

    if (d != NULL) {
        word32 order = 1000000000;
        word32 digit;

        if (number == 0) {
            d[i++] = '0';
        }
        else {
            while (order) {
                digit = number / order;
                if (i > 0 || digit != 0) {
                    d[i++] = (char)digit + '0';
                }
                if (digit != 0)
                    number %= digit * order;
                if (order > 1)
                    order /= 10;
                else
                    order = 0;
            }
        }
        d[i] = 0;
    }

    return i;
}


/* Decode ITU-T X.690 OID format to a string representation
 * return string length */
static int DecodePolicyOID(char *out, word32 outSz, byte *in, word32 inSz)
{
    word32 val, idx = 0, nb_bytes;
    size_t w_bytes = 0;

    if (out == NULL || in == NULL || outSz < 4 || inSz < 2)
        return BAD_FUNC_ARG;

    /* first two byte must be interpreted as : 40 * int1 + int2 */
    val = (word16)in[idx++];

    w_bytes = Word32ToString(out, val / 40);
    out[w_bytes++] = '.';
    w_bytes += Word32ToString(out+w_bytes, val % 40);

    while (idx < inSz) {
        /* init value */
        val = 0;
        nb_bytes = 0;

        /* check that output size is ok */
        if (w_bytes > (outSz - 3))
            return BUFFER_E;

        /* first bit is used to set if value is coded on 1 or multiple bytes */
        while ((in[idx+nb_bytes] & 0x80))
            nb_bytes++;

        if (!nb_bytes)
            val = (word32)(in[idx++] & 0x7f);
        else {
            word32 base = 1, tmp = nb_bytes;

            while (tmp != 0) {
                val += (word32)(in[idx+tmp] & 0x7f) * base;
                base *= 128;
                tmp--;
            }
            val += (word32)(in[idx++] & 0x7f) * base;

            idx += nb_bytes;
        }

        out[w_bytes++] = '.';
        w_bytes += Word32ToString(out+w_bytes, val);
    }

    return 0;
}
#endif /* WOLFSSL_CERT_EXT && !WOLFSSL_SEP */

#if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
    /* Reference: https://tools.ietf.org/html/rfc5280#section-4.2.1.4 */
    static int DecodeCertPolicy(byte* input, int sz, DecodedCert* cert)
    {
        word32 idx = 0;
        int total_length = 0, policy_length = 0, length = 0;

        WOLFSSL_ENTER("DecodeCertPolicy");

        if (GetSequence(input, &idx, &total_length, sz) < 0) {
            WOLFSSL_MSG("\tGet CertPolicy total seq failed");
            return ASN_PARSE_E;
        }

        /* Validate total length (2 is the CERT_POLICY_OID+SEQ) */
        if ((total_length + 2) != sz) {
            WOLFSSL_MSG("\tCertPolicy length mismatch");
            return ASN_PARSE_E;
        }

        /* Unwrap certificatePolicies */
        do {
            if (GetSequence(input, &idx, &policy_length, sz) < 0) {
                WOLFSSL_MSG("\tGet CertPolicy seq failed");
                return ASN_PARSE_E;
            }

            if (input[idx++] != ASN_OBJECT_ID) {
                WOLFSSL_MSG("\tCertPolicy isn't OID");
                return ASN_PARSE_E;
            }
            policy_length--;

            if (GetLength(input, &idx, &length, sz) < 0) {
                WOLFSSL_MSG("\tGet CertPolicy length failed");
                return ASN_PARSE_E;
            }
            policy_length--;

            if (length > 0) {
                /* Verify length won't overrun buffer */
                if (length > (sz - (int)idx)) {
                    WOLFSSL_MSG("\tCertPolicy length exceeds input buffer");
                    return ASN_PARSE_E;
                }

    #if defined(WOLFSSL_SEP)
                cert->deviceType = (byte*)XMALLOC(length, cert->heap,
                                                  DYNAMIC_TYPE_X509_EXT);
                if (cert->deviceType == NULL) {
                    WOLFSSL_MSG("\tCouldn't alloc memory for deviceType");
                    return MEMORY_E;
                }
                cert->deviceTypeSz = length;
                XMEMCPY(cert->deviceType, input + idx, length);
                break;
    #elif defined(WOLFSSL_CERT_EXT)
                /* decode cert policy */
                if (DecodePolicyOID(cert->extCertPolicies[cert->extCertPoliciesNb], MAX_CERTPOL_SZ,
                                    input + idx, length) != 0) {
                    WOLFSSL_MSG("\tCouldn't decode CertPolicy");
                    return ASN_PARSE_E;
                }
                cert->extCertPoliciesNb++;
    #else
                WOLFSSL_LEAVE("DecodeCertPolicy : unsupported mode", 0);
                return 0;
    #endif
            }
            idx += policy_length;
        } while((int)idx < total_length
    #if defined(WOLFSSL_CERT_EXT)
            && cert->extCertPoliciesNb < MAX_CERTPOL_NB
    #endif
        );

        WOLFSSL_LEAVE("DecodeCertPolicy", 0);
        return 0;
    }
#endif /* WOLFSSL_SEP */

#ifndef NO_ASN_TIME
static int DecodeCertExtensions(DecodedCert* cert)
/*
 *  Processing the Certificate Extensions. This does not modify the current
 *  index. It is works starting with the recorded extensions pointer.
 */
{
    int ret;
    word32 idx = 0;
    int sz = cert->extensionsSz;
    byte* input = cert->extensions;
    int length;
    word32 oid;
    byte critical = 0;
    byte criticalFail = 0;

    WOLFSSL_ENTER("DecodeCertExtensions");

    if (input == NULL || sz == 0)
        return BAD_FUNC_ARG;

    if (input[idx++] != ASN_EXTENSIONS) {
        WOLFSSL_MSG("\tfail: should be an EXTENSIONS");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: invalid length");
        return ASN_PARSE_E;
    }

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE (1)");
        return ASN_PARSE_E;
    }

    while (idx < (word32)sz) {
        if (GetSequence(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if ((ret = GetObjectId(input, &idx, &oid, oidCertExtType, sz)) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ret;
        }

        /* check for critical flag */
        critical = 0;
        if (input[idx] == ASN_BOOLEAN) {
            int boolLength = 0;
            idx++;
            if (GetLength(input, &idx, &boolLength, sz) < 0) {
                WOLFSSL_MSG("\tfail: critical boolean length");
                return ASN_PARSE_E;
            }
            if (input[idx++])
                critical = 1;
        }

        /* process the extension based on the OID */
        if (input[idx++] != ASN_OCTET_STRING) {
            WOLFSSL_MSG("\tfail: should be an OCTET STRING");
            return ASN_PARSE_E;
        }

        if (GetLength(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: extension data length");
            return ASN_PARSE_E;
        }

        switch (oid) {
            case BASIC_CA_OID:
                #ifdef OPENSSL_EXTRA
                    cert->extBasicConstSet = 1;
                    cert->extBasicConstCrit = critical;
                #endif
                if (DecodeBasicCaConstraint(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case CRL_DIST_OID:
                if (DecodeCrlDist(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case AUTH_INFO_OID:
                if (DecodeAuthInfo(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case ALT_NAMES_OID:
                #ifdef OPENSSL_EXTRA
                    cert->extSubjAltNameSet = 1;
                    cert->extSubjAltNameCrit = critical;
                #endif
                if (DecodeAltNames(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case AUTH_KEY_OID:
                cert->extAuthKeyIdSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extAuthKeyIdCrit = critical;
                #endif
                if (DecodeAuthKeyId(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case SUBJ_KEY_OID:
                cert->extSubjKeyIdSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extSubjKeyIdCrit = critical;
                #endif
                if (DecodeSubjKeyId(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case CERT_POLICY_OID:
                #ifdef WOLFSSL_SEP
                    #ifdef OPENSSL_EXTRA
                        cert->extCertPolicySet = 1;
                        cert->extCertPolicyCrit = critical;
                    #endif
                #endif
                #if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
                    if (DecodeCertPolicy(&input[idx], length, cert) < 0) {
                        return ASN_PARSE_E;
                    }
                #else
                    WOLFSSL_MSG("Certificate Policy extension not supported yet.");
                #endif
                break;

            case KEY_USAGE_OID:
                cert->extKeyUsageSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extKeyUsageCrit = critical;
                #endif
                if (DecodeKeyUsage(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            case EXT_KEY_USAGE_OID:
                cert->extExtKeyUsageSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extExtKeyUsageCrit = critical;
                #endif
                if (DecodeExtKeyUsage(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;

            #ifndef IGNORE_NAME_CONSTRAINTS
            case NAME_CONS_OID:
                cert->extNameConstraintSet = 1;
                #ifdef OPENSSL_EXTRA
                    cert->extNameConstraintCrit = critical;
                #endif
                if (DecodeNameConstraints(&input[idx], length, cert) < 0)
                    return ASN_PARSE_E;
                break;
            #endif /* IGNORE_NAME_CONSTRAINTS */

            case INHIBIT_ANY_OID:
                WOLFSSL_MSG("Inhibit anyPolicy extension not supported yet.");
                break;

            default:
                /* While it is a failure to not support critical extensions,
                 * still parse the certificate ignoring the unsupported
                 * extension to allow caller to accept it with the verify
                 * callback. */
                if (critical)
                    criticalFail = 1;
                break;
        }
        idx += length;
    }

    return criticalFail ? ASN_CRIT_EXT_E : 0;
}


int ParseCert(DecodedCert* cert, int type, int verify, void* cm)
{
    int   ret;
    char* ptr;

    ret = ParseCertRelative(cert, type, verify, cm);
    if (ret < 0)
        return ret;

    if (cert->subjectCNLen > 0) {
        ptr = (char*) XMALLOC(cert->subjectCNLen + 1, cert->heap,
                              DYNAMIC_TYPE_SUBJECT_CN);
        if (ptr == NULL)
            return MEMORY_E;
        XMEMCPY(ptr, cert->subjectCN, cert->subjectCNLen);
        ptr[cert->subjectCNLen] = '\0';
        cert->subjectCN = ptr;
        cert->subjectCNStored = 1;
    }

    if (cert->keyOID == RSAk &&
                          cert->publicKey != NULL  && cert->pubKeySize > 0) {
        ptr = (char*) XMALLOC(cert->pubKeySize, cert->heap,
                              DYNAMIC_TYPE_PUBLIC_KEY);
        if (ptr == NULL)
            return MEMORY_E;
        XMEMCPY(ptr, cert->publicKey, cert->pubKeySize);
        cert->publicKey = (byte *)ptr;
        cert->pubKeyStored = 1;
    }

    return ret;
}
#endif /* !NO_ASN_TIME */


/* from SSL proper, for locking can't do find here anymore */
#ifdef __cplusplus
    extern "C" {
#endif
    WOLFSSL_LOCAL Signer* GetCA(void* signers, byte* hash);
    #ifndef NO_SKID
        WOLFSSL_LOCAL Signer* GetCAByName(void* signers, byte* hash);
    #endif
#ifdef __cplusplus
    }
#endif


#if defined(WOLFCRYPT_ONLY) || defined(NO_CERTS)

/* dummy functions, not using wolfSSL so don't need actual ones */
Signer* GetCA(void* signers, byte* hash)
{
    (void)hash;

    return (Signer*)signers;
}

#ifndef NO_SKID
Signer* GetCAByName(void* signers, byte* hash)
{
    (void)hash;

    return (Signer*)signers;
}
#endif /* NO_SKID */

#endif /* WOLFCRYPT_ONLY || NO_CERTS */

#ifndef NO_ASN_TIME
int ParseCertRelative(DecodedCert* cert, int type, int verify, void* cm)
{
    word32 confirmOID;
    int    ret;
    int    badDate     = 0;
    int    criticalExt = 0;

    if ((ret = DecodeToKey(cert, verify)) < 0) {
        if (ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E)
            badDate = ret;
        else
            return ret;
    }

    WOLFSSL_MSG("Parsed Past Key");

    if (cert->srcIdx < cert->sigIndex) {
        #ifndef ALLOW_V1_EXTENSIONS
            if (cert->version < 2) {
                WOLFSSL_MSG("    v1 and v2 certs not allowed extensions");
                return ASN_VERSION_E;
            }
        #endif
        /* save extensions */
        cert->extensions    = &cert->source[cert->srcIdx];
        cert->extensionsSz  =  cert->sigIndex - cert->srcIdx;
        cert->extensionsIdx = cert->srcIdx;   /* for potential later use */

        if ((ret = DecodeCertExtensions(cert)) < 0) {
            if (ret == ASN_CRIT_EXT_E)
                criticalExt = ret;
            else
                return ret;
        }

        /* advance past extensions */
        cert->srcIdx =  cert->sigIndex;
    }

    if ((ret = GetAlgoId(cert->source, &cert->srcIdx, &confirmOID,
                         oidSigType, cert->maxIdx)) < 0)
        return ret;

    if ((ret = GetSignature(cert)) < 0)
        return ret;

    if (confirmOID != cert->signatureOID)
        return ASN_SIG_OID_E;

    #ifndef NO_SKID
        if (cert->extSubjKeyIdSet == 0
                          && cert->publicKey != NULL && cert->pubKeySize > 0) {
        #ifdef NO_SHA
            ret = wc_Sha256Hash(cert->publicKey, cert->pubKeySize,
                                                            cert->extSubjKeyId);
        #else
            ret = wc_ShaHash(cert->publicKey, cert->pubKeySize,
                                                            cert->extSubjKeyId);
        #endif
            if (ret != 0)
                return ret;
        }
    #endif

   if (verify != NO_VERIFY && type != CA_TYPE && type != TRUSTED_PEER_TYPE) {
        Signer* ca = NULL;
        #ifndef NO_SKID
            if (cert->extAuthKeyIdSet)
                ca = GetCA(cm, cert->extAuthKeyId);
            if (ca == NULL)
                ca = GetCAByName(cm, cert->issuerHash);
        #else /* NO_SKID */
            ca = GetCA(cm, cert->issuerHash);
        #endif /* NO SKID */
        WOLFSSL_MSG("About to verify certificate signature");

        if (ca) {
            if (cert->isCA) {
                if (ca->pathLengthSet) {
                    if (ca->pathLength == 0) {
                        WOLFSSL_MSG("CA with path length 0 signing a CA");
                        return ASN_PATHLEN_INV_E;
                    }
                    if (cert->pathLengthSet &&
                        cert->pathLength >= ca->pathLength) {

                        WOLFSSL_MSG("CA signing CA with longer path length");
                        return ASN_PATHLEN_INV_E;
                    }
                }
            }

#ifdef HAVE_OCSP
            /* Need the ca's public key hash for OCSP */
    #ifdef NO_SHA
            ret = wc_Sha256Hash(ca->publicKey, ca->pubKeySize,
                                cert->issuerKeyHash);
    #else /* NO_SHA */
            ret = wc_ShaHash(ca->publicKey, ca->pubKeySize,
                                cert->issuerKeyHash);
    #endif /* NO_SHA */
            if (ret != 0)
                return ret;
#endif /* HAVE_OCSP */

            if (verify == VERIFY) {
                /* try to confirm/verify signature */
                if (!ConfirmSignature(cert->source + cert->certBegin,
                            cert->sigIndex - cert->certBegin,
                        ca->publicKey, ca->pubKeySize, ca->keyOID,
                        cert->signature, cert->sigLength, cert->signatureOID,
                        cert->heap)) {
                    WOLFSSL_MSG("Confirm signature failed");
                    return ASN_SIG_CONFIRM_E;
                }
                #ifndef IGNORE_NAME_CONSTRAINTS
                /* check that this cert's name is permitted by the signer's
                 * name constraints */
                if (!ConfirmNameConstraints(ca, cert)) {
                    WOLFSSL_MSG("Confirm name constraint failed");
                    return ASN_NAME_INVALID_E;
                }
                #endif /* IGNORE_NAME_CONSTRAINTS */
            }
        }
        else {
            /* no signer */
            WOLFSSL_MSG("No CA signer to verify with");
            return ASN_NO_SIGNER_E;
        }
    }

    if (badDate != 0)
        return badDate;

    if (criticalExt != 0)
        return criticalExt;

    return 0;
}
#endif /* !NO_ASN_TIME */

/* Create and init an new signer */
Signer* MakeSigner(void* heap)
{
    Signer* signer = (Signer*) XMALLOC(sizeof(Signer), heap,
                                       DYNAMIC_TYPE_SIGNER);
    if (signer) {
        signer->pubKeySize = 0;
        signer->keyOID     = 0;
        signer->publicKey  = NULL;
        signer->nameLen    = 0;
        signer->name       = NULL;
        #ifndef IGNORE_NAME_CONSTRAINTS
            signer->permittedNames = NULL;
            signer->excludedNames = NULL;
        #endif /* IGNORE_NAME_CONSTRAINTS */
        signer->pathLengthSet = 0;
        signer->pathLength = 0;
        signer->next       = NULL;
    }
    (void)heap;

    return signer;
}


/* Free an individual signer */
void FreeSigner(Signer* signer, void* heap)
{
    XFREE(signer->name, heap, DYNAMIC_TYPE_SUBJECT_CN);
    XFREE(signer->publicKey, heap, DYNAMIC_TYPE_PUBLIC_KEY);
    #ifndef IGNORE_NAME_CONSTRAINTS
        if (signer->permittedNames)
            FreeNameSubtrees(signer->permittedNames, heap);
        if (signer->excludedNames)
            FreeNameSubtrees(signer->excludedNames, heap);
    #endif
    XFREE(signer, heap, DYNAMIC_TYPE_SIGNER);

    (void)heap;
}


/* Free the whole singer table with number of rows */
void FreeSignerTable(Signer** table, int rows, void* heap)
{
    int i;

    for (i = 0; i < rows; i++) {
        Signer* signer = table[i];
        while (signer) {
            Signer* next = signer->next;
            FreeSigner(signer, heap);
            signer = next;
        }
        table[i] = NULL;
    }
}

#ifdef WOLFSSL_TRUST_PEER_CERT
/* Free an individual trusted peer cert */
void FreeTrustedPeer(TrustedPeerCert* tp, void* heap)
{
    if (tp == NULL) {
        return;
    }

    if (tp->name) {
        XFREE(tp->name, heap, DYNAMIC_TYPE_SUBJECT_CN);
    }

    if (tp->sig) {
        XFREE(tp->sig, heap, DYNAMIC_TYPE_SIGNATURE);
    }
    #ifndef IGNORE_NAME_CONSTRAINTS
        if (tp->permittedNames)
            FreeNameSubtrees(tp->permittedNames, heap);
        if (tp->excludedNames)
            FreeNameSubtrees(tp->excludedNames, heap);
    #endif
    XFREE(tp, heap, DYNAMIC_TYPE_CERT);

    (void)heap;
}

/* Free the whole Trusted Peer linked list */
void FreeTrustedPeerTable(TrustedPeerCert** table, int rows, void* heap)
{
    int i;

    for (i = 0; i < rows; i++) {
        TrustedPeerCert* tp = table[i];
        while (tp) {
            TrustedPeerCert* next = tp->next;
            FreeTrustedPeer(tp, heap);
            tp = next;
        }
        table[i] = NULL;
    }
}
#endif /* WOLFSSL_TRUST_PEER_CERT */

WOLFSSL_LOCAL int SetMyVersion(word32 version, byte* output, int header)
{
    int i = 0;

    if (output == NULL)
        return BAD_FUNC_ARG;

    if (header) {
        output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
        output[i++] = ASN_BIT_STRING;
    }
    output[i++] = ASN_INTEGER;
    output[i++] = 0x01;
    output[i++] = (byte)version;

    return i;
}


WOLFSSL_LOCAL int SetSerialNumber(const byte* sn, word32 snSz, byte* output)
{
    int result = 0;

    WOLFSSL_ENTER("SetSerialNumber");

    if (sn == NULL || output == NULL)
        return BAD_FUNC_ARG;

    if (snSz <= EXTERNAL_SERIAL_SIZE) {
        output[0] = ASN_INTEGER;
        /* The serial number is always positive. When encoding the
         * INTEGER, if the MSB is 1, add a padding zero to keep the
         * number positive. */
        if (sn[0] & 0x80) {
            output[1] = (byte)snSz + 1;
            output[2] = 0;
            XMEMCPY(&output[3], sn, snSz);
            result = snSz + 3;
        }
        else {
            output[1] = (byte)snSz;
            XMEMCPY(&output[2], sn, snSz);
            result = snSz + 2;
        }
    }
    return result;
}

WOLFSSL_LOCAL int GetSerialNumber(const byte* input, word32* inOutIdx,
    byte* serial, int* serialSz, word32 maxIdx)
{
    int result = 0;
    byte b;

    WOLFSSL_ENTER("GetSerialNumber");

    if (serial == NULL || input == NULL || serialSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* First byte is ASN type */
    if ((*inOutIdx+1) > maxIdx) {
        WOLFSSL_MSG("Bad idx first");
        return BUFFER_E;
    }
    b = input[*inOutIdx];
    *inOutIdx += 1;

    if (b != ASN_INTEGER) {
        WOLFSSL_MSG("Expecting Integer");
        return ASN_PARSE_E;
    }

    if (GetLength(input, inOutIdx, serialSz, maxIdx) < 0) {
        return ASN_PARSE_E;
    }

    /* serial size check */
    if (*serialSz < 0 || *serialSz > EXTERNAL_SERIAL_SIZE) {
        WOLFSSL_MSG("Serial size bad");
        return ASN_PARSE_E;
    }

    /* serial size check against max index */
    if ((*inOutIdx + *serialSz) > maxIdx) {
        WOLFSSL_MSG("Bad idx serial");
        return BUFFER_E;
    }

    /* only check padding and return serial if length is greater than 1 */
    if (*serialSz > 0) {
        /* skip padding */
        if (input[*inOutIdx] == 0x00) {
            *serialSz -= 1;
            *inOutIdx += 1;
        }

        /* return serial */
        XMEMCPY(serial, &input[*inOutIdx], *serialSz);
        *inOutIdx += *serialSz;
    }

    return result;
}



const char* BEGIN_CERT         = "-----BEGIN CERTIFICATE-----";
const char* END_CERT           = "-----END CERTIFICATE-----";
const char* BEGIN_CERT_REQ     = "-----BEGIN CERTIFICATE REQUEST-----";
const char* END_CERT_REQ       = "-----END CERTIFICATE REQUEST-----";
const char* BEGIN_DH_PARAM     = "-----BEGIN DH PARAMETERS-----";
const char* END_DH_PARAM       = "-----END DH PARAMETERS-----";
const char* BEGIN_X509_CRL     = "-----BEGIN X509 CRL-----";
const char* END_X509_CRL       = "-----END X509 CRL-----";
const char* BEGIN_RSA_PRIV     = "-----BEGIN RSA PRIVATE KEY-----";
const char* END_RSA_PRIV       = "-----END RSA PRIVATE KEY-----";
const char* BEGIN_PRIV_KEY     = "-----BEGIN PRIVATE KEY-----";
const char* END_PRIV_KEY       = "-----END PRIVATE KEY-----";
const char* BEGIN_ENC_PRIV_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const char* END_ENC_PRIV_KEY   = "-----END ENCRYPTED PRIVATE KEY-----";
const char* BEGIN_EC_PRIV      = "-----BEGIN EC PRIVATE KEY-----";
const char* END_EC_PRIV        = "-----END EC PRIVATE KEY-----";
const char* BEGIN_DSA_PRIV     = "-----BEGIN DSA PRIVATE KEY-----";
const char* END_DSA_PRIV       = "-----END DSA PRIVATE KEY-----";
const char* BEGIN_PUB_KEY      = "-----BEGIN PUBLIC KEY-----";
const char* END_PUB_KEY        = "-----END PUBLIC KEY-----";

#if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)

/* Used for compatibility API */
int wc_DerToPem(const byte* der, word32 derSz,
                byte* output, word32 outSz, int type)
{
    return wc_DerToPemEx(der, derSz, output, outSz, NULL, type);
}

/* convert der buffer to pem into output, can't do inplace, der and output
   need to be different */
int wc_DerToPemEx(const byte* der, word32 derSz, byte* output, word32 outSz,
             byte *cipher_info, int type)
{
#ifdef WOLFSSL_SMALL_STACK
    char* header = NULL;
    char* footer = NULL;
#else
    char header[40 + HEADER_ENCRYPTED_KEY_SIZE];
    char footer[40];
#endif

    int headerLen = 40 + HEADER_ENCRYPTED_KEY_SIZE;
    int footerLen = 40;
    int i;
    int err;
    int outLen;   /* return length or error */

    if (der == output)      /* no in place conversion */
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    header = (char*)XMALLOC(headerLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (header == NULL)
        return MEMORY_E;

    footer = (char*)XMALLOC(footerLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (footer == NULL) {
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif
    if (type == CERT_TYPE) {
        XSTRNCPY(header, BEGIN_CERT, headerLen);
        XSTRNCAT(header, "\n", 1);

        XSTRNCPY(footer, END_CERT, footerLen);
        XSTRNCAT(footer, "\n", 1);
    }
    else if (type == PRIVATEKEY_TYPE) {
        XSTRNCPY(header, BEGIN_RSA_PRIV, headerLen);
        XSTRNCAT(header, "\n", 1);

        XSTRNCPY(footer, END_RSA_PRIV, footerLen);
        XSTRNCAT(footer, "\n", 1);
    }
#ifndef NO_DSA
    else if (type == DSA_PRIVATEKEY_TYPE) {
        XSTRNCPY(header, BEGIN_DSA_PRIV, headerLen);
        XSTRNCAT(header, "\n", 1);

        XSTRNCPY(footer, END_DSA_PRIV, footerLen);
        XSTRNCAT(footer, "\n", 1);
    }
#endif
#ifdef HAVE_ECC
    else if (type == ECC_PRIVATEKEY_TYPE) {
        XSTRNCPY(header, BEGIN_EC_PRIV, headerLen);
        XSTRNCAT(header, "\n", 1);

        XSTRNCPY(footer, END_EC_PRIV, footerLen);
        XSTRNCAT(footer, "\n", 1);
    }
#endif
#ifdef WOLFSSL_CERT_REQ
    else if (type == CERTREQ_TYPE)
    {
        XSTRNCPY(header, BEGIN_CERT_REQ, headerLen);
        XSTRNCAT(header, "\n", 1);

        XSTRNCPY(footer, END_CERT_REQ, footerLen);
        XSTRNCAT(footer, "\n", 1);
    }
#endif
#ifdef HAVE_CRL
    else if (type == CRL_TYPE)
    {
        XSTRNCPY(header, BEGIN_X509_CRL, headerLen);
        XSTRNCAT(header, "\n", 1);

        XSTRNCPY(footer, END_X509_CRL, footerLen);
        XSTRNCAT(footer, "\n", 1);
    }
#endif
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    /* extra header information for encrypted key */
    if (cipher_info != NULL) {
        XSTRNCAT(header, "Proc-Type: 4,ENCRYPTED\n", 23);
        XSTRNCAT(header, "DEK-Info: ", 10);
        XSTRNCAT(header, (char*)cipher_info, XSTRLEN((char*)cipher_info));
        XSTRNCAT(header, "\n\n", 2);
    }

    headerLen = (int)XSTRLEN(header);
    footerLen = (int)XSTRLEN(footer);

    if (!der || !output) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    /* don't even try if outSz too short */
    if (outSz < headerLen + footerLen + derSz) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }

    /* header */
    XMEMCPY(output, header, headerLen);
    i = headerLen;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    /* body */
    outLen = outSz - (headerLen + footerLen);  /* input to Base64_Encode */
    if ( (err = Base64_Encode(der, derSz, output + i, (word32*)&outLen)) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return err;
    }
    i += outLen;

    /* footer */
    if ( (i + footerLen) > (int)outSz) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BAD_FUNC_ARG;
    }
    XMEMCPY(output + i, footer, footerLen);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(footer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return outLen + headerLen + footerLen;
}

#endif /* WOLFSSL_KEY_GEN || WOLFSSL_CERT_GEN */

#if !defined(NO_RSA) && (defined(WOLFSSL_CERT_GEN) || (defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)))
/* USER RSA ifdef portions used instead of refactor in consideration for
   possible fips build */
/* Write a public RSA key to output */
static int SetRsaPublicKey(byte* output, RsaKey* key,
                           int outLen, int with_header)
{
#ifdef WOLFSSL_SMALL_STACK
    byte* n = NULL;
    byte* e = NULL;
#else
    byte n[MAX_RSA_INT_SZ];
    byte e[MAX_RSA_E_SZ];
#endif
    byte seq[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ + 1];  /* trailing 0 */
    int  nSz;
    int  eSz;
    int  seqSz;
    int  lenSz;
    int  idx;
    int  rawLen;
    int  leadingBit;
    int  err;

    if (output == NULL || key == NULL || outLen < MAX_SEQ_SZ)
        return BAD_FUNC_ARG;

    /* n */
#ifdef WOLFSSL_SMALL_STACK
    n = (byte*)XMALLOC(MAX_RSA_INT_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (n == NULL)
        return MEMORY_E;
#endif

#ifdef HAVE_USER_RSA
    leadingBit = wc_Rsa_leading_bit(key->n);
    rawLen = wc_Rsa_unsigned_bin_size(key->n) + leadingBit;
#else
    leadingBit = mp_leading_bit(&key->n);
    rawLen = mp_unsigned_bin_size(&key->n) + leadingBit;
#endif
    n[0] = ASN_INTEGER;
    nSz  = SetLength(rawLen, n + 1) + 1;  /* int tag */

    if ( (nSz + rawLen) <= MAX_RSA_INT_SZ) {
        if (leadingBit)
            n[nSz] = 0;
#ifdef HAVE_USER_RSA
        err = wc_Rsa_to_unsigned_bin(key->n, n + nSz, rawLen);
#else
        err = mp_to_unsigned_bin(&key->n, n + nSz + leadingBit);
#endif
        if (err == MP_OKAY)
            nSz += rawLen;
        else {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return MP_TO_E;
        }
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    /* e */
#ifdef WOLFSSL_SMALL_STACK
    e = (byte*)XMALLOC(MAX_RSA_E_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (e == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return MEMORY_E;
    }
#endif

#ifdef HAVE_USER_RSA
    leadingBit = wc_Rsa_leading_bit(key->e);
    rawLen = wc_Rsa_unsigned_bin_size(key->e) + leadingBit;
#else
    leadingBit = mp_leading_bit(&key->e);
    rawLen = mp_unsigned_bin_size(&key->e) + leadingBit;
#endif
    e[0] = ASN_INTEGER;
    eSz  = SetLength(rawLen, e + 1) + 1;  /* int tag */

    if ( (eSz + rawLen) < MAX_RSA_E_SZ) {
        if (leadingBit)
            e[eSz] = 0;
#ifdef HAVE_USER_RSA
        err = wc_Rsa_to_unsigned_bin(key->e, e + eSz, rawLen);
#else
        err = mp_to_unsigned_bin(&key->e, e + eSz + leadingBit);
#endif
        if (err == MP_OKAY)
            eSz += rawLen;
        else {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return MP_TO_E;
        }
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    seqSz  = SetSequence(nSz + eSz, seq);

    /* check output size */
    if ( (seqSz + nSz + eSz) > outLen) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(n,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(e,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    /* headers */
    if (with_header) {
        int  algoSz;
#ifdef WOLFSSL_SMALL_STACK
        byte* algo = NULL;

        algo = (byte*)XMALLOC(MAX_ALGO_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (algo == NULL) {
            XFREE(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(e, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#else
        byte algo[MAX_ALGO_SZ];
#endif
        algoSz = SetAlgoID(RSAk, algo, oidKeyType, 0);
        lenSz  = SetLength(seqSz + nSz + eSz + 1, len);
        len[lenSz++] = 0;   /* trailing 0 */

        /* write, 1 is for ASN_BIT_STRING */
        idx = SetSequence(nSz + eSz + seqSz + lenSz + 1 + algoSz, output);

        /* check output size */
        if ( (idx + algoSz + 1 + lenSz + seqSz + nSz + eSz) > outLen) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(n,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(e,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(algo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            #endif

            return BUFFER_E;
        }

        /* algo */
        XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        /* bit string */
        output[idx++] = ASN_BIT_STRING;
        /* length */
        XMEMCPY(output + idx, len, lenSz);
        idx += lenSz;
#ifdef WOLFSSL_SMALL_STACK
        XFREE(algo, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    }
    else
        idx = 0;

    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx += seqSz;
    /* n */
    XMEMCPY(output + idx, n, nSz);
    idx += nSz;
    /* e */
    XMEMCPY(output + idx, e, eSz);
    idx += eSz;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(n,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(e,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return idx;
}
#endif /* !defined(NO_RSA) && (defined(WOLFSSL_CERT_GEN) ||
                               defined(WOLFSSL_KEY_GEN)) */


#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA) && !defined(HAVE_USER_RSA)


static mp_int* GetRsaInt(RsaKey* key, int idx)
{
    if (idx == 0)
        return &key->n;
    if (idx == 1)
        return &key->e;
    if (idx == 2)
        return &key->d;
    if (idx == 3)
        return &key->p;
    if (idx == 4)
        return &key->q;
    if (idx == 5)
        return &key->dP;
    if (idx == 6)
        return &key->dQ;
    if (idx == 7)
        return &key->u;

    return NULL;
}


/* Release Tmp RSA resources */
static INLINE void FreeTmpRsas(byte** tmps, void* heap)
{
    int i;

    (void)heap;

    for (i = 0; i < RSA_INTS; i++)
        XFREE(tmps[i], heap, DYNAMIC_TYPE_RSA);
}


/* Convert RsaKey key to DER format, write to output (inLen), return bytes
   written */
int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen)
{
    word32 seqSz, verSz, rawLen, intTotalLen = 0;
    word32 sizes[RSA_INTS];
    int    i, j, outLen, ret = 0, lbit;

    byte  seq[MAX_SEQ_SZ];
    byte  ver[MAX_VERSION_SZ];
    byte* tmps[RSA_INTS];

    if (!key || !output)
        return BAD_FUNC_ARG;

    if (key->type != RSA_PRIVATE)
        return BAD_FUNC_ARG;

    for (i = 0; i < RSA_INTS; i++)
        tmps[i] = NULL;

    /* write all big ints from key to DER tmps */
    for (i = 0; i < RSA_INTS; i++) {
        mp_int* keyInt = GetRsaInt(key, i);

        /* leading zero */
        lbit = mp_leading_bit(keyInt);
        rawLen = mp_unsigned_bin_size(keyInt) + lbit;

        tmps[i] = (byte*)XMALLOC(rawLen + MAX_SEQ_SZ, key->heap,
                                 DYNAMIC_TYPE_RSA);
        if (tmps[i] == NULL) {
            ret = MEMORY_E;
            break;
        }

        tmps[i][0] = ASN_INTEGER;
        sizes[i] = SetLength(rawLen, tmps[i] + 1) + 1 + lbit; /* tag & lbit */

        if (sizes[i] <= MAX_SEQ_SZ) {
            int err;

            /* leading zero */
            if (lbit)
                tmps[i][sizes[i]-1] = 0x00;

            err = mp_to_unsigned_bin(keyInt, tmps[i] + sizes[i]);
            if (err == MP_OKAY) {
                sizes[i] += (rawLen-lbit); /* lbit included in rawLen */
                intTotalLen += sizes[i];
            }
            else {
                ret = err;
                break;
            }
        }
        else {
            ret = ASN_INPUT_E;
            break;
        }
    }

    if (ret != 0) {
        FreeTmpRsas(tmps, key->heap);
        return ret;
    }

    /* make headers */
    verSz = SetMyVersion(0, ver, FALSE);
    seqSz = SetSequence(verSz + intTotalLen, seq);

    outLen = seqSz + verSz + intTotalLen;
    if (outLen > (int)inLen)
        return BAD_FUNC_ARG;

    /* write to output */
    XMEMCPY(output, seq, seqSz);
    j = seqSz;
    XMEMCPY(output + j, ver, verSz);
    j += verSz;

    for (i = 0; i < RSA_INTS; i++) {
        XMEMCPY(output + j, tmps[i], sizes[i]);
        j += sizes[i];
    }
    FreeTmpRsas(tmps, key->heap);

    return outLen;
}


/* Convert Rsa Public key to DER format, write to output (inLen), return bytes
   written */
int wc_RsaKeyToPublicDer(RsaKey* key, byte* output, word32 inLen)
{
    return SetRsaPublicKey(output, key, inLen, 1);
}

#endif /* WOLFSSL_KEY_GEN && !NO_RSA */


#if defined(WOLFSSL_CERT_GEN) && !defined(NO_RSA)


#ifndef WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MIN

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* WOLFSSL_HAVE_MIN */


/* Initialize and Set Certificate defaults:
   version    = 3 (0x2)
   serial     = 0
   sigType    = SHA_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
*/
void wc_InitCert(Cert* cert)
{
    cert->version    = 2;   /* version 3 is hex 2 */
    cert->sigType    = CTC_SHAwRSA;
    cert->daysValid  = 500;
    cert->selfSigned = 1;
    cert->isCA       = 0;
    cert->bodySz     = 0;
#ifdef WOLFSSL_ALT_NAMES
    cert->altNamesSz   = 0;
    cert->beforeDateSz = 0;
    cert->afterDateSz  = 0;
#endif
#ifdef WOLFSSL_CERT_EXT
    cert->skidSz = 0;
    cert->akidSz = 0;
    cert->keyUsage = 0;
    cert->certPoliciesNb = 0;
    XMEMSET(cert->akid, 0, CTC_MAX_AKID_SIZE);
    XMEMSET(cert->skid, 0, CTC_MAX_SKID_SIZE);
    XMEMSET(cert->certPolicies, 0, CTC_MAX_CERTPOL_NB*CTC_MAX_CERTPOL_SZ);
#endif
    cert->keyType    = RSA_KEY;
    XMEMSET(cert->serial, 0, CTC_SERIAL_SIZE);

    cert->issuer.country[0] = '\0';
    cert->issuer.countryEnc = CTC_PRINTABLE;
    cert->issuer.state[0] = '\0';
    cert->issuer.stateEnc = CTC_UTF8;
    cert->issuer.locality[0] = '\0';
    cert->issuer.localityEnc = CTC_UTF8;
    cert->issuer.sur[0] = '\0';
    cert->issuer.surEnc = CTC_UTF8;
    cert->issuer.org[0] = '\0';
    cert->issuer.orgEnc = CTC_UTF8;
    cert->issuer.unit[0] = '\0';
    cert->issuer.unitEnc = CTC_UTF8;
    cert->issuer.commonName[0] = '\0';
    cert->issuer.commonNameEnc = CTC_UTF8;
    cert->issuer.email[0] = '\0';

    cert->subject.country[0] = '\0';
    cert->subject.countryEnc = CTC_PRINTABLE;
    cert->subject.state[0] = '\0';
    cert->subject.stateEnc = CTC_UTF8;
    cert->subject.locality[0] = '\0';
    cert->subject.localityEnc = CTC_UTF8;
    cert->subject.sur[0] = '\0';
    cert->subject.surEnc = CTC_UTF8;
    cert->subject.org[0] = '\0';
    cert->subject.orgEnc = CTC_UTF8;
    cert->subject.unit[0] = '\0';
    cert->subject.unitEnc = CTC_UTF8;
    cert->subject.commonName[0] = '\0';
    cert->subject.commonNameEnc = CTC_UTF8;
    cert->subject.email[0] = '\0';

#ifdef WOLFSSL_CERT_REQ
    cert->challengePw[0] ='\0';
#endif
#ifdef WOLFSSL_HEAP_TEST
    cert->heap = (void*)WOLFSSL_HEAP_TEST;
#else
    cert->heap = NULL;
#endif
}


/* DER encoded x509 Certificate */
typedef struct DerCert {
    byte size[MAX_LENGTH_SZ];          /* length encoded */
    byte version[MAX_VERSION_SZ];      /* version encoded */
    byte serial[CTC_SERIAL_SIZE + MAX_LENGTH_SZ]; /* serial number encoded */
    byte sigAlgo[MAX_ALGO_SZ];         /* signature algo encoded */
    byte issuer[ASN_NAME_MAX];         /* issuer  encoded */
    byte subject[ASN_NAME_MAX];        /* subject encoded */
    byte validity[MAX_DATE_SIZE*2 + MAX_SEQ_SZ*2];  /* before and after dates */
    byte publicKey[MAX_PUBLIC_KEY_SZ]; /* rsa / ntru public key encoded */
    byte ca[MAX_CA_SZ];                /* basic constraint CA true size */
    byte extensions[MAX_EXTENSIONS_SZ]; /* all extensions */
#ifdef WOLFSSL_CERT_EXT
    byte skid[MAX_KID_SZ];             /* Subject Key Identifier extension */
    byte akid[MAX_KID_SZ];             /* Authority Key Identifier extension */
    byte keyUsage[MAX_KEYUSAGE_SZ];    /* Key Usage extension */
    byte certPolicies[MAX_CERTPOL_NB*MAX_CERTPOL_SZ]; /* Certificate Policies */
#endif
#ifdef WOLFSSL_CERT_REQ
    byte attrib[MAX_ATTRIB_SZ];        /* Cert req attributes encoded */
#endif
#ifdef WOLFSSL_ALT_NAMES
    byte altNames[CTC_MAX_ALT_SIZE];   /* Alternative Names encoded */
#endif
    int  sizeSz;                       /* encoded size length */
    int  versionSz;                    /* encoded version length */
    int  serialSz;                     /* encoded serial length */
    int  sigAlgoSz;                    /* encoded sig alog length */
    int  issuerSz;                     /* encoded issuer length */
    int  subjectSz;                    /* encoded subject length */
    int  validitySz;                   /* encoded validity length */
    int  publicKeySz;                  /* encoded public key length */
    int  caSz;                         /* encoded CA extension length */
#ifdef WOLFSSL_CERT_EXT
    int  skidSz;                       /* encoded SKID extension length */
    int  akidSz;                       /* encoded SKID extension length */
    int  keyUsageSz;                   /* encoded KeyUsage extension length */
    int  certPoliciesSz;               /* encoded CertPolicies extension length*/
#endif
#ifdef WOLFSSL_ALT_NAMES
    int  altNamesSz;                   /* encoded AltNames extension length */
#endif
    int  extensionsSz;                 /* encoded extensions total length */
    int  total;                        /* total encoded lengths */
#ifdef WOLFSSL_CERT_REQ
    int  attribSz;
#endif
} DerCert;


#ifdef WOLFSSL_CERT_REQ

/* Write a set header to output */
static word32 SetUTF8String(word32 len, byte* output)
{
    output[0] = ASN_UTF8STRING;
    return SetLength(len, output + 1) + 1;
}

#endif /* WOLFSSL_CERT_REQ */


/* Write a serial number to output */
static int SetSerial(const byte* serial, byte* output)
{
    int length = 0;

    output[length++] = ASN_INTEGER;
    length += SetLength(CTC_SERIAL_SIZE, &output[length]);
    XMEMCPY(&output[length], serial, CTC_SERIAL_SIZE);

    return length + CTC_SERIAL_SIZE;
}

#endif /* defined(WOLFSSL_CERT_GEN) && !defined(NO_RSA) */
#if defined(HAVE_ECC) && (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))

/* Write a public ECC key to output */
static int SetEccPublicKey(byte* output, ecc_key* key, int with_header)
{
    byte len[MAX_LENGTH_SZ + TRAILING_ZERO];
    int  algoSz;
    int  curveSz;
    int  lenSz;
    int  idx;
    word32 pubSz = ECC_BUFSIZE;
#ifdef WOLFSSL_SMALL_STACK
    byte* algo = NULL;
    byte* curve = NULL;
    byte* pub = NULL;
#else
    byte algo[MAX_ALGO_SZ];
    byte curve[MAX_ALGO_SZ];
    byte pub[ECC_BUFSIZE];
#endif

#ifdef WOLFSSL_SMALL_STACK
    pub = (byte*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL)
        return MEMORY_E;
#endif

    int ret = wc_ecc_export_x963(key, pub, &pubSz);
    if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    /* headers */
    if (with_header) {
#ifdef WOLFSSL_SMALL_STACK
        curve = (byte*)XMALLOC(MAX_ALGO_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (curve == NULL) {
            XFREE(pub, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#endif
        curveSz = SetCurve(key, curve);
        if (curveSz <= 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(curve, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(pub,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return curveSz;
        }

#ifdef WOLFSSL_SMALL_STACK
        algo = (byte*)XMALLOC(MAX_ALGO_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (algo == NULL) {
            XFREE(curve, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(pub,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#endif
        algoSz  = SetAlgoID(ECDSAk, algo, oidKeyType, curveSz);

        lenSz   = SetLength(pubSz + TRAILING_ZERO, len);
        len[lenSz++] = 0;   /* trailing 0 */

        /* write, 1 is for ASN_BIT_STRING */
        idx = SetSequence(pubSz + curveSz + lenSz + 1 + algoSz, output);
        /* algo */
        XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
       /* curve */
        XMEMCPY(output + idx, curve, curveSz);
        idx += curveSz;
        /* bit string */
        output[idx++] = ASN_BIT_STRING;
        /* length */
        XMEMCPY(output + idx, len, lenSz);
        idx += lenSz;
    }
    else
        idx = 0;

    /* pub */
    XMEMCPY(output + idx, pub, pubSz);
    idx += pubSz;

#ifdef WOLFSSL_SMALL_STACK
    if (with_header) {
        XFREE(algo,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(curve, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(pub,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return idx;
}


/* returns the size of buffer used, the public ECC key in DER format is stored
   in output buffer
   with_AlgCurve is a flag for when to include a header that has the Algorithm
   and Curve infromation */
int wc_EccPublicKeyToDer(ecc_key* key, byte* output, word32 inLen,
                                                              int with_AlgCurve)
{
    word32 infoSz = 0;
    word32 keySz  = 0;
    int ret;

    if (output == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (with_AlgCurve) {
        /* buffer space for algorithm/curve */
        infoSz += MAX_SEQ_SZ;
        infoSz += 2 * MAX_ALGO_SZ;

        /* buffer space for public key sequence */
        infoSz += MAX_SEQ_SZ;
        infoSz += TRAILING_ZERO;
    }

    if ((ret = wc_ecc_export_x963(key, NULL, &keySz)) != LENGTH_ONLY_E) {
        WOLFSSL_MSG("Error in getting ECC public key size");
        return ret;
    }

    if (inLen < keySz + infoSz) {
        return BUFFER_E;
    }

    return SetEccPublicKey(output, key, with_AlgCurve);
}
#endif /* HAVE_ECC && (WOLFSSL_CERT_GEN || WOLFSSL_KEY_GEN) */
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_RSA)

static INLINE byte itob(int number)
{
    return (byte)number + 0x30;
}


/* write time to output, format */
static void SetTime(struct tm* date, byte* output)
{
    int i = 0;

    output[i++] = itob((date->tm_year % 10000) / 1000);
    output[i++] = itob((date->tm_year % 1000)  /  100);
    output[i++] = itob((date->tm_year % 100)   /   10);
    output[i++] = itob( date->tm_year % 10);

    output[i++] = itob(date->tm_mon / 10);
    output[i++] = itob(date->tm_mon % 10);

    output[i++] = itob(date->tm_mday / 10);
    output[i++] = itob(date->tm_mday % 10);

    output[i++] = itob(date->tm_hour / 10);
    output[i++] = itob(date->tm_hour % 10);

    output[i++] = itob(date->tm_min / 10);
    output[i++] = itob(date->tm_min % 10);

    output[i++] = itob(date->tm_sec / 10);
    output[i++] = itob(date->tm_sec % 10);

    output[i] = 'Z';  /* Zulu profile */
}


#ifdef WOLFSSL_ALT_NAMES

/* Copy Dates from cert, return bytes written */
static int CopyValidity(byte* output, Cert* cert)
{
    int seqSz;

    WOLFSSL_ENTER("CopyValidity");

    /* headers and output */
    seqSz = SetSequence(cert->beforeDateSz + cert->afterDateSz, output);
    XMEMCPY(output + seqSz, cert->beforeDate, cert->beforeDateSz);
    XMEMCPY(output + seqSz + cert->beforeDateSz, cert->afterDate,
                                                 cert->afterDateSz);
    return seqSz + cert->beforeDateSz + cert->afterDateSz;
}

#endif


/* for systems where mktime() doesn't normalize fully */
static void RebuildTime(time_t* in, struct tm* out)
{
    #if defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
        out = localtime_r(in, out);
    #else
        (void)in;
        (void)out;
    #endif
}


/* Set Date validity from now until now + daysValid
 * return size in bytes written to output, 0 on error */
static int SetValidity(byte* output, int daysValid)
{
    byte before[MAX_DATE_SIZE];
    byte  after[MAX_DATE_SIZE];

    int beforeSz;
    int afterSz;
    int seqSz;

    time_t     ticks;
    time_t     normalTime;
    struct tm* now;
    struct tm* tmpTime = NULL;
    struct tm  local;

#if defined(NEED_TMP_TIME)
    /* for use with gmtime_r */
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    (void)tmpTime;
#endif

    ticks = XTIME(0);
    now   = XGMTIME(&ticks, tmpTime);

    if (now == NULL) {
        WOLFSSL_MSG("XGMTIME failed");
        return 0;   /* error */
    }

    /* before now */
    local = *now;
    before[0] = ASN_GENERALIZED_TIME;
    beforeSz  = SetLength(ASN_GEN_TIME_SZ, before + 1) + 1;  /* gen tag */

    /* subtract 1 day for more compliance */
    local.tm_mday -= 1;
    normalTime = mktime(&local);
    RebuildTime(&normalTime, &local);

    /* adjust */
    local.tm_year += 1900;
    local.tm_mon  +=    1;

    SetTime(&local, before + beforeSz);
    beforeSz += ASN_GEN_TIME_SZ;

    /* after now + daysValid */
    local = *now;
    after[0] = ASN_GENERALIZED_TIME;
    afterSz  = SetLength(ASN_GEN_TIME_SZ, after + 1) + 1;  /* gen tag */

    /* add daysValid */
    local.tm_mday += daysValid;
    normalTime = mktime(&local);
    RebuildTime(&normalTime, &local);

    /* adjust */
    local.tm_year += 1900;
    local.tm_mon  +=    1;

    SetTime(&local, after + afterSz);
    afterSz += ASN_GEN_TIME_SZ;

    /* headers and output */
    seqSz = SetSequence(beforeSz + afterSz, output);
    XMEMCPY(output + seqSz, before, beforeSz);
    XMEMCPY(output + seqSz + beforeSz, after, afterSz);

    return seqSz + beforeSz + afterSz;
}


/* ASN Encoded Name field */
typedef struct EncodedName {
    int  nameLen;                /* actual string value length */
    int  totalLen;               /* total encoded length */
    int  type;                   /* type of name */
    int  used;                   /* are we actually using this one */
    byte encoded[CTC_NAME_SIZE * 2]; /* encoding */
} EncodedName;


/* Get Which Name from index */
static const char* GetOneName(CertName* name, int idx)
{
    switch (idx) {
    case 0:
       return name->country;

    case 1:
       return name->state;

    case 2:
       return name->locality;

    case 3:
       return name->sur;

    case 4:
       return name->org;

    case 5:
       return name->unit;

    case 6:
       return name->commonName;

    case 7:
       return name->email;

    default:
       return 0;
    }
}


/* Get Which Name Encoding from index */
static char GetNameType(CertName* name, int idx)
{
    switch (idx) {
    case 0:
       return name->countryEnc;

    case 1:
       return name->stateEnc;

    case 2:
       return name->localityEnc;

    case 3:
       return name->surEnc;

    case 4:
       return name->orgEnc;

    case 5:
       return name->unitEnc;

    case 6:
       return name->commonNameEnc;

    default:
       return 0;
    }
}


/* Get ASN Name from index */
static byte GetNameId(int idx)
{
    switch (idx) {
    case 0:
       return ASN_COUNTRY_NAME;

    case 1:
       return ASN_STATE_NAME;

    case 2:
       return ASN_LOCALITY_NAME;

    case 3:
       return ASN_SUR_NAME;

    case 4:
       return ASN_ORG_NAME;

    case 5:
       return ASN_ORGUNIT_NAME;

    case 6:
       return ASN_COMMON_NAME;

    case 7:
       /* email uses different id type */
       return 0;

    default:
       return 0;
    }
}

/*
 Extensions ::= SEQUENCE OF Extension

 Extension ::= SEQUENCE {
 extnId     OBJECT IDENTIFIER,
 critical   BOOLEAN DEFAULT FALSE,
 extnValue  OCTET STRING }
 */

/* encode all extensions, return total bytes written */
static int SetExtensions(byte* out, word32 outSz, int *IdxInOut,
                         const byte* ext, int extSz)
{
    if (out == NULL || IdxInOut == NULL || ext == NULL)
        return BAD_FUNC_ARG;

    if (outSz < (word32)(*IdxInOut+extSz))
        return BUFFER_E;

    XMEMCPY(&out[*IdxInOut], ext, extSz);  /* extensions */
    *IdxInOut += extSz;

    return *IdxInOut;
}

/* encode extensions header, return total bytes written */
static int SetExtensionsHeader(byte* out, word32 outSz, int extSz)
{
    byte sequence[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ];
    int seqSz, lenSz, idx = 0;

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < 3)
        return BUFFER_E;

    seqSz = SetSequence(extSz, sequence);

    /* encode extensions length provided */
    lenSz = SetLength(extSz+seqSz, len);

    if (outSz < (word32)(lenSz+seqSz+1))
        return BUFFER_E;

    out[idx++] = ASN_EXTENSIONS; /* extensions id */
    XMEMCPY(&out[idx], len, lenSz);  /* length */
    idx += lenSz;

    XMEMCPY(&out[idx], sequence, seqSz);  /* sequence */
    idx += seqSz;

    return idx;
}


/* encode CA basic constraint true, return total bytes written */
static int SetCa(byte* out, word32 outSz)
{
    static const byte ca[] = { 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,
                               0x05, 0x30, 0x03, 0x01, 0x01, 0xff };

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < sizeof(ca))
        return BUFFER_E;

    XMEMCPY(out, ca, sizeof(ca));

    return (int)sizeof(ca);
}


#ifdef WOLFSSL_CERT_EXT
/* encode OID and associated value, return total bytes written */
static int SetOidValue(byte* out, word32 outSz, const byte *oid, word32 oidSz,
                       byte *in, word32 inSz)
{
    int idx = 0;

    if (out == NULL || oid == NULL || in == NULL)
        return BAD_FUNC_ARG;

    if (outSz < 3)
        return BUFFER_E;

    /* sequence,  + 1 => byte to put value size */
    idx = SetSequence(inSz + oidSz + 1, out);

    if (outSz < idx + inSz + oidSz + 1)
        return BUFFER_E;

    XMEMCPY(out+idx, oid, oidSz);
    idx += oidSz;
    out[idx++] = (byte)inSz;
    XMEMCPY(out+idx, in, inSz);

    return (idx+inSz);
}

/* encode Subject Key Identifier, return total bytes written
 * RFC5280 : non-critical */
static int SetSKID(byte* output, word32 outSz, byte *input, word32 length)
{
    byte skid_len[MAX_LENGTH_SZ];
    byte skid_enc_len[MAX_LENGTH_SZ];
    int idx = 0, skid_lenSz, skid_enc_lenSz;
    static const byte skid_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04 };

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

    /* length of value */
    skid_lenSz = SetLength(length, skid_len);

    /* length of encoded value */
    skid_enc_lenSz = SetLength(length + skid_lenSz + 1, skid_enc_len);

    if (outSz < 3)
        return BUFFER_E;

    /* sequence, + 1 => byte to put type size */
    idx = SetSequence(length + sizeof(skid_oid) + skid_lenSz + skid_enc_lenSz+1,
                      output);

    if (outSz < length + sizeof(skid_oid) + skid_lenSz + skid_enc_lenSz + 1)
        return BUFFER_E;

    /* put oid */
    XMEMCPY(output+idx, skid_oid, sizeof(skid_oid));
    idx += sizeof(skid_oid);

    /* put encoded len */
    XMEMCPY(output+idx, skid_enc_len, skid_enc_lenSz);
    idx += skid_enc_lenSz;

    /* put type */
    output[idx++] = ASN_OCTET_STRING;

    /* put value len */
    XMEMCPY(output+idx, skid_len, skid_lenSz);
    idx += skid_lenSz;

    /* put value */
    XMEMCPY(output+idx, input, length);
    idx += length;

    return idx;
}

/* encode Authority Key Identifier, return total bytes written
 * RFC5280 : non-critical */
static int SetAKID(byte* output, word32 outSz,
                                         byte *input, word32 length, void* heap)
{
    byte    *enc_val;
    int     ret, enc_valSz;
    static const byte akid_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04};
    static const byte akid_cs[] = { 0x80 };

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

    enc_val = (byte *)XMALLOC(length+3+sizeof(akid_cs), heap,
                               DYNAMIC_TYPE_TMP_BUFFER);
    if (enc_val == NULL)
        return MEMORY_E;

    /* sequence for ContentSpec & value */
    enc_valSz = SetOidValue(enc_val, length+3+sizeof(akid_cs),
                            akid_cs, sizeof(akid_cs), input, length);
    if (enc_valSz == 0) {
        XFREE(enc_val, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return 0;
    }

    ret = SetOidValue(output, outSz, akid_oid,
                      sizeof(akid_oid), enc_val, enc_valSz);

    XFREE(enc_val, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* encode Key Usage, return total bytes written
 * RFC5280 : critical */
static int SetKeyUsage(byte* output, word32 outSz, word16 input)
{
    byte ku[5];
    int unusedBits = 0;
    static const byte keyusage_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f,
                                         0x01, 0x01, 0xff, 0x04};

    if (output == NULL)
        return BAD_FUNC_ARG;

    /* Key Usage is a BitString */
    ku[0] = ASN_BIT_STRING;

    /* put the Bit String size */
    if (input > 255) {
        ku[1] = (byte)3;

        /* compute unused bits */
        while (((((input >> 8) & 0xff) >> unusedBits) & 0x01) == 0)
            unusedBits++;
    }
    else {
        ku[1] = (byte)2;

        /* compute unused bits */
        while (((input >> unusedBits) & 0x01) == 0)
            unusedBits++;
    }

    /* put unused bits value */
    ku[2] = (byte)unusedBits;

    /* compute byte value */
    ku[3] = (byte)(input & 0xff);
    if (input > 255)
        ku[4] = (byte)((input >> 8) & 0xff);

    return SetOidValue(output, outSz, keyusage_oid, sizeof(keyusage_oid),
                       ku, (int)ku[1]+2);
}

/* Encode OID string representation to ITU-T X.690 format */
static int EncodePolicyOID(byte *out, word32 *outSz, const char *in, void* heap)
{
    word32 val, idx = 0, nb_val;
    char *token, *str, *ptr;
    word32 len;

    if (out == NULL || outSz == NULL || *outSz < 2 || in == NULL)
        return BAD_FUNC_ARG;

    len = (word32)XSTRLEN(in);

    str = (char *)XMALLOC(len+1, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (str == NULL)
        return MEMORY_E;

    XSTRNCPY(str, in, len);
    str[len] = 0x00;

    nb_val = 0;

    /* parse value, and set corresponding Policy OID value */
    token = XSTRTOK(str, ".", &ptr);
    while (token != NULL)
    {
        val = (word32)atoi(token);

        if (nb_val == 0) {
            if (val > 2) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return ASN_OBJECT_ID_E;
            }

            out[idx] = (byte)(40 * val);
        }
        else if (nb_val == 1) {
            if (val > 127) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return ASN_OBJECT_ID_E;
            }

            if (idx > *outSz) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return BUFFER_E;
            }

            out[idx++] += (byte)val;
        }
        else {
            word32  tb = 0, x;
            int     i = 0;
            byte    oid[MAX_OID_SZ];

            while (val >= 128) {
                x = val % 128;
                val /= 128;
                oid[i++] = (byte) (((tb++) ? 0x80 : 0) | x);
            }

            if ((idx+(word32)i) > *outSz) {
                XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
                return BUFFER_E;
            }

            oid[i] = (byte) (((tb++) ? 0x80 : 0) | val);

            /* push value in the right order */
            while (i >= 0)
                out[idx++] = oid[i--];
        }

        token = XSTRTOK(NULL, ".", &ptr);
        nb_val++;
    }

    *outSz = idx;

    XFREE(str, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

/* encode Certificate Policies, return total bytes written
 * each input value must be ITU-T X.690 formatted : a.b.c...
 * input must be an array of values with a NULL terminated for the latest
 * RFC5280 : non-critical */
static int SetCertificatePolicies(byte *output,
                                  word32 outputSz,
                                  char input[MAX_CERTPOL_NB][MAX_CERTPOL_SZ],
                                  word16 nb_certpol,
                                  void* heap)
{
    byte    oid[MAX_OID_SZ],
            der_oid[MAX_CERTPOL_NB][MAX_OID_SZ],
            out[MAX_CERTPOL_SZ];
    word32  oidSz;
    word32  outSz, i = 0, der_oidSz[MAX_CERTPOL_NB];
    int     ret;

    static const byte certpol_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04 };
    static const byte oid_oid[] = { 0x06 };

    if (output == NULL || input == NULL || nb_certpol > MAX_CERTPOL_NB)
        return BAD_FUNC_ARG;

    for (i = 0; i < nb_certpol; i++) {
        oidSz = sizeof(oid);
        XMEMSET(oid, 0, oidSz);

        ret = EncodePolicyOID(oid, &oidSz, input[i], heap);
        if (ret != 0)
            return ret;

        /* compute sequence value for the oid */
        ret = SetOidValue(der_oid[i], MAX_OID_SZ, oid_oid,
                          sizeof(oid_oid), oid, oidSz);
        if (ret <= 0)
            return ret;
        else
            der_oidSz[i] = (word32)ret;
    }

    /* concatenate oid, keep two byte for sequence/size of the created value */
    for (i = 0, outSz = 2; i < nb_certpol; i++) {
        XMEMCPY(out+outSz, der_oid[i], der_oidSz[i]);
        outSz += der_oidSz[i];
    }

    /* add sequence */
    ret = SetSequence(outSz-2, out);
    if (ret <= 0)
        return ret;

    /* add Policy OID to compute final value */
    return SetOidValue(output, outputSz, certpol_oid, sizeof(certpol_oid),
                      out, outSz);
}
#endif /* WOLFSSL_CERT_EXT */

#ifdef WOLFSSL_ALT_NAMES
/* encode Alternative Names, return total bytes written */
static int SetAltNames(byte *out, word32 outSz, byte *input, word32 length)
{
    if (out == NULL || input == NULL)
        return BAD_FUNC_ARG;

    if (outSz < length)
        return BUFFER_E;

    /* Alternative Names come from certificate or computed by
     * external function, so already encoded. Just copy value */
    XMEMCPY(out, input, length);
    return length;
}
#endif /* WOLFSL_ALT_NAMES */


/* encode CertName into output, return total bytes written */
int SetName(byte* output, word32 outputSz, CertName* name)
{
    int          totalBytes = 0, i, idx;
#ifdef WOLFSSL_SMALL_STACK
    EncodedName* names = NULL;
#else
    EncodedName  names[NAME_ENTRIES];
#endif

    if (output == NULL || name == NULL)
        return BAD_FUNC_ARG;

    if (outputSz < 3)
        return BUFFER_E;

#ifdef WOLFSSL_SMALL_STACK
    names = (EncodedName*)XMALLOC(sizeof(EncodedName) * NAME_ENTRIES, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (names == NULL)
        return MEMORY_E;
#endif

    for (i = 0; i < NAME_ENTRIES; i++) {
        const char* nameStr = GetOneName(name, i);
        if (nameStr) {
            /* bottom up */
            byte firstLen[MAX_LENGTH_SZ];
            byte secondLen[MAX_LENGTH_SZ];
            byte sequence[MAX_SEQ_SZ];
            byte set[MAX_SET_SZ];

            int email = i == (NAME_ENTRIES - 1) ? 1 : 0;
            int strLen  = (int)XSTRLEN(nameStr);
            int thisLen = strLen;
            int firstSz, secondSz, seqSz, setSz;

            if (strLen == 0) { /* no user data for this item */
                names[i].used = 0;
                continue;
            }

            /* Restrict country code size */
            if (i == 0 && strLen != CTC_COUNTRY_SIZE) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return ASN_COUNTRY_SIZE_E;
            }

            secondSz = SetLength(strLen, secondLen);
            thisLen += secondSz;
            if (email) {
                thisLen += EMAIL_JOINT_LEN;
                thisLen ++;                               /* id type */
                firstSz  = SetLength(EMAIL_JOINT_LEN, firstLen);
            }
            else {
                thisLen++;                                 /* str type */
                thisLen++;                                 /* id  type */
                thisLen += JOINT_LEN;
                firstSz = SetLength(JOINT_LEN + 1, firstLen);
            }
            thisLen += firstSz;
            thisLen++;                                /* object id */

            seqSz = SetSequence(thisLen, sequence);
            thisLen += seqSz;
            setSz = SetSet(thisLen, set);
            thisLen += setSz;

            if (thisLen > (int)sizeof(names[i].encoded)) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return BUFFER_E;
            }

            /* store it */
            idx = 0;
            /* set */
            XMEMCPY(names[i].encoded, set, setSz);
            idx += setSz;
            /* seq */
            XMEMCPY(names[i].encoded + idx, sequence, seqSz);
            idx += seqSz;
            /* asn object id */
            names[i].encoded[idx++] = ASN_OBJECT_ID;
            /* first length */
            XMEMCPY(names[i].encoded + idx, firstLen, firstSz);
            idx += firstSz;
            if (email) {
                const byte EMAIL_OID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                           0x01, 0x09, 0x01, 0x16 };
                /* email joint id */
                XMEMCPY(names[i].encoded + idx, EMAIL_OID, sizeof(EMAIL_OID));
                idx += (int)sizeof(EMAIL_OID);
            }
            else {
                /* joint id */
                byte bType = GetNameId(i);
                names[i].encoded[idx++] = 0x55;
                names[i].encoded[idx++] = 0x04;
                /* id type */
                names[i].encoded[idx++] = bType;
                /* str type */
                names[i].encoded[idx++] = GetNameType(name, i);
            }
            /* second length */
            XMEMCPY(names[i].encoded + idx, secondLen, secondSz);
            idx += secondSz;
            /* str value */
            XMEMCPY(names[i].encoded + idx, nameStr, strLen);
            idx += strLen;

            totalBytes += idx;
            names[i].totalLen = idx;
            names[i].used = 1;
        }
        else
            names[i].used = 0;
    }

    /* header */
    idx = SetSequence(totalBytes, output);
    totalBytes += idx;
    if (totalBytes > ASN_NAME_MAX) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return BUFFER_E;
    }

    for (i = 0; i < NAME_ENTRIES; i++) {
        if (names[i].used) {
            if (outputSz < (word32)(idx+names[i].totalLen)) {
#ifdef WOLFSSL_SMALL_STACK
                XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
                return BUFFER_E;
            }

            XMEMCPY(output + idx, names[i].encoded, names[i].totalLen);
            idx += names[i].totalLen;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return totalBytes;
}

/* encode info from cert into DER encoded format */
static int EncodeCert(Cert* cert, DerCert* der, RsaKey* rsaKey, ecc_key* eccKey,
                      WC_RNG* rng, const byte* ntruKey, word16 ntruSz)
{
    int ret;

    (void)eccKey;
    (void)ntruKey;
    (void)ntruSz;

    if (cert == NULL || der == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    /* init */
    XMEMSET(der, 0, sizeof(DerCert));

    /* version */
    der->versionSz = SetMyVersion(cert->version, der->version, TRUE);

    /* serial number */
    ret = wc_RNG_GenerateBlock(rng, cert->serial, CTC_SERIAL_SIZE);
    if (ret != 0)
        return ret;

    cert->serial[0] = 0x01;   /* ensure positive */
    der->serialSz  = SetSerial(cert->serial, der->serial);

    /* signature algo */
    der->sigAlgoSz = SetAlgoID(cert->sigType, der->sigAlgo, oidSigType, 0);
    if (der->sigAlgoSz <= 0)
        return ALGO_ID_E;

    /* public key */
    if (cert->keyType == RSA_KEY) {
        if (rsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey,
                                           sizeof(der->publicKey), 1);
        if (der->publicKeySz <= 0)
            return PUBLIC_KEY_E;
    }

#ifdef HAVE_ECC
    if (cert->keyType == ECC_KEY) {
        if (eccKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey, 1);
        if (der->publicKeySz <= 0)
            return PUBLIC_KEY_E;
    }
#endif /* HAVE_ECC */

#ifdef HAVE_NTRU
    if (cert->keyType == NTRU_KEY) {
        word32 rc;
        word16 encodedSz;

        rc  = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo( ntruSz,
                                                   ntruKey, &encodedSz, NULL);
        if (rc != NTRU_OK)
            return PUBLIC_KEY_E;
        if (encodedSz > MAX_PUBLIC_KEY_SZ)
            return PUBLIC_KEY_E;

        rc  = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo( ntruSz,
                                         ntruKey, &encodedSz, der->publicKey);
        if (rc != NTRU_OK)
            return PUBLIC_KEY_E;

        der->publicKeySz = encodedSz;
    }
#endif /* HAVE_NTRU */

    der->validitySz = 0;
#ifdef WOLFSSL_ALT_NAMES
    /* date validity copy ? */
    if (cert->beforeDateSz && cert->afterDateSz) {
        der->validitySz = CopyValidity(der->validity, cert);
        if (der->validitySz <= 0)
            return DATE_E;
    }
#endif

    /* date validity */
    if (der->validitySz == 0) {
        der->validitySz = SetValidity(der->validity, cert->daysValid);
        if (der->validitySz <= 0)
            return DATE_E;
    }

    /* subject name */
    der->subjectSz = SetName(der->subject, sizeof(der->subject), &cert->subject);
    if (der->subjectSz <= 0)
        return SUBJECT_E;

    /* issuer name */
    der->issuerSz = SetName(der->issuer, sizeof(der->issuer), cert->selfSigned ?
             &cert->subject : &cert->issuer);
    if (der->issuerSz <= 0)
        return ISSUER_E;

    /* set the extensions */
    der->extensionsSz = 0;

    /* CA */
    if (cert->isCA) {
        der->caSz = SetCa(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
    else
        der->caSz = 0;

#ifdef WOLFSSL_ALT_NAMES
    /* Alternative Name */
    if (cert->altNamesSz) {
        der->altNamesSz = SetAltNames(der->altNames, sizeof(der->altNames),
                                      cert->altNames, cert->altNamesSz);
        if (der->altNamesSz <= 0)
            return ALT_NAME_E;

        der->extensionsSz += der->altNamesSz;
    }
    else
        der->altNamesSz = 0;
#endif

#ifdef WOLFSSL_CERT_EXT
    /* SKID */
    if (cert->skidSz) {
        /* check the provided SKID size */
        if (cert->skidSz > (int)sizeof(der->skid))
            return SKID_E;

        der->skidSz = SetSKID(der->skid, sizeof(der->skid),
                              cert->skid, cert->skidSz);
        if (der->skidSz <= 0)
            return SKID_E;

        der->extensionsSz += der->skidSz;
    }
    else
        der->skidSz = 0;

    /* AKID */
    if (cert->akidSz) {
        /* check the provided AKID size */
        if (cert->akidSz > (int)sizeof(der->akid))
            return AKID_E;

        der->akidSz = SetAKID(der->akid, sizeof(der->akid),
                              cert->akid, cert->akidSz, cert->heap);
        if (der->akidSz <= 0)
            return AKID_E;

        der->extensionsSz += der->akidSz;
    }
    else
        der->akidSz = 0;

    /* Key Usage */
    if (cert->keyUsage != 0){
        der->keyUsageSz = SetKeyUsage(der->keyUsage, sizeof(der->keyUsage),
                                      cert->keyUsage);
        if (der->keyUsageSz <= 0)
            return KEYUSAGE_E;

        der->extensionsSz += der->keyUsageSz;
    }
    else
        der->keyUsageSz = 0;

    /* Certificate Policies */
    if (cert->certPoliciesNb != 0) {
        der->certPoliciesSz = SetCertificatePolicies(der->certPolicies,
                                                     sizeof(der->certPolicies),
                                                     cert->certPolicies,
                                                     cert->certPoliciesNb,
                                                     cert->heap);
        if (der->certPoliciesSz <= 0)
            return CERTPOLICIES_E;

        der->extensionsSz += der->certPoliciesSz;
    }
    else
        der->certPoliciesSz = 0;
#endif /* WOLFSSL_CERT_EXT */

    /* put extensions */
    if (der->extensionsSz > 0) {

        /* put the start of extensions sequence (ID, Size) */
        der->extensionsSz = SetExtensionsHeader(der->extensions,
                                                sizeof(der->extensions),
                                                der->extensionsSz);
        if (der->extensionsSz <= 0)
            return EXTENSIONS_E;

        /* put CA */
        if (der->caSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->ca, der->caSz);
            if (ret == 0)
                return EXTENSIONS_E;
        }

#ifdef WOLFSSL_ALT_NAMES
        /* put Alternative Names */
        if (der->altNamesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->altNames, der->altNamesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif

#ifdef WOLFSSL_CERT_EXT
        /* put SKID */
        if (der->skidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->skid, der->skidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put AKID */
        if (der->akidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->akid, der->akidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put KeyUsage */
        if (der->keyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->keyUsage, der->keyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put Certificate Policies */
        if (der->certPoliciesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->certPolicies, der->certPoliciesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif /* WOLFSSL_CERT_EXT */
    }

    der->total = der->versionSz + der->serialSz + der->sigAlgoSz +
        der->publicKeySz + der->validitySz + der->subjectSz + der->issuerSz +
        der->extensionsSz;

    return 0;
}


/* write DER encoded cert to buffer, size already checked */
static int WriteCertBody(DerCert* der, byte* buffer)
{
    int idx;

    /* signed part header */
    idx = SetSequence(der->total, buffer);
    /* version */
    XMEMCPY(buffer + idx, der->version, der->versionSz);
    idx += der->versionSz;
    /* serial */
    XMEMCPY(buffer + idx, der->serial, der->serialSz);
    idx += der->serialSz;
    /* sig algo */
    XMEMCPY(buffer + idx, der->sigAlgo, der->sigAlgoSz);
    idx += der->sigAlgoSz;
    /* issuer */
    XMEMCPY(buffer + idx, der->issuer, der->issuerSz);
    idx += der->issuerSz;
    /* validity */
    XMEMCPY(buffer + idx, der->validity, der->validitySz);
    idx += der->validitySz;
    /* subject */
    XMEMCPY(buffer + idx, der->subject, der->subjectSz);
    idx += der->subjectSz;
    /* public key */
    XMEMCPY(buffer + idx, der->publicKey, der->publicKeySz);
    idx += der->publicKeySz;
    if (der->extensionsSz) {
        /* extensions */
        XMEMCPY(buffer + idx, der->extensions, min(der->extensionsSz,
                                                   (int)sizeof(der->extensions)));
        idx += der->extensionsSz;
    }

    return idx;
}


/* Make RSA signature from buffer (sz), write to sig (sigSz) */
static int MakeSignature(const byte* buffer, int sz, byte* sig, int sigSz,
                         RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng,
                         int sigAlgoType)
{
    int encSigSz, digestSz, typeH = 0, ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* digest;
#else
    byte digest[WC_MAX_DIGEST_SIZE]; /* max size */
#endif
#ifdef WOLFSSL_SMALL_STACK
    byte* encSig;
#else
    byte encSig[MAX_DER_DIGEST_SZ];
#endif

    (void)digest;
    (void)digestSz;
    (void)encSig;
    (void)encSigSz;
    (void)typeH;

    (void)buffer;
    (void)sz;
    (void)sig;
    (void)sigSz;
    (void)rsaKey;
    (void)eccKey;
    (void)rng;

#ifdef WOLFSSL_SMALL_STACK
    digest = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (digest == NULL)
        return 0; /* not confirmed */
#endif

    switch (sigAlgoType) {
    #ifndef NO_MD5
        case CTC_MD5wRSA:
        if ((ret = wc_Md5Hash(buffer, sz, digest)) == 0) {
            typeH    = MD5h;
            digestSz = MD5_DIGEST_SIZE;
        }
        break;
    #endif
    #ifndef NO_SHA
        case CTC_SHAwRSA:
        case CTC_SHAwECDSA:
        if ((ret = wc_ShaHash(buffer, sz, digest)) == 0) {
            typeH    = SHAh;
            digestSz = SHA_DIGEST_SIZE;
        }
        break;
    #endif
    #ifndef NO_SHA256
        case CTC_SHA256wRSA:
        case CTC_SHA256wECDSA:
        if ((ret = wc_Sha256Hash(buffer, sz, digest)) == 0) {
            typeH    = SHA256h;
            digestSz = SHA256_DIGEST_SIZE;
        }
        break;
    #endif
    #ifdef WOLFSSL_SHA512
        case CTC_SHA512wRSA:
        case CTC_SHA512wECDSA:
        if ((ret = wc_Sha512Hash(buffer, sz, digest)) == 0) {
            typeH    = SHA256h;
            digestSz = SHA256_DIGEST_SIZE;
        }
        break;
    #endif
        default:
            WOLFSSL_MSG("MakeSignautre called with unsupported type");
            ret = ALGO_ID_E;
    }

    if (ret != 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }

#ifdef WOLFSSL_SMALL_STACK
    encSig = (byte*)XMALLOC(MAX_DER_DIGEST_SZ,
                                                 NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (encSig == NULL) {
        XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    ret = ALGO_ID_E;

#ifndef NO_RSA
    if (rsaKey) {
        /* signature */
        encSigSz = wc_EncodeSignature(encSig, digest, digestSz, typeH);
        ret = 0;
        do {
#if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_RsaAsyncWait(ret, rsaKey);
#endif
            if (ret >= 0) {
                ret = wc_RsaSSL_Sign(encSig, encSigSz, sig, sigSz, rsaKey, rng);
            }
        } while (ret == WC_PENDING_E);
    }
#endif

#ifdef HAVE_ECC
    if (!rsaKey && eccKey) {
        word32 outSz = sigSz;
        ret = wc_ecc_sign_hash(digest, digestSz, sig, &outSz, rng, eccKey);

        if (ret == 0)
            ret = outSz;
    }
#endif

#ifdef WOLFSSL_SMALL_STACK
    XFREE(digest, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(encSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/* add signature to end of buffer, size of buffer assumed checked, return
   new length */
static int AddSignature(byte* buffer, int bodySz, const byte* sig, int sigSz,
                        int sigAlgoType)
{
    byte seq[MAX_SEQ_SZ];
    int  idx = bodySz, seqSz;

    /* algo */
    idx += SetAlgoID(sigAlgoType, buffer + idx, oidSigType, 0);
    /* bit string */
    buffer[idx++] = ASN_BIT_STRING;
    /* length */
    idx += SetLength(sigSz + 1, buffer + idx);
    buffer[idx++] = 0;   /* trailing 0 */
    /* signature */
    XMEMCPY(buffer + idx, sig, sigSz);
    idx += sigSz;

    /* make room for overall header */
    seqSz = SetSequence(idx, seq);
    XMEMMOVE(buffer + seqSz, buffer, idx);
    XMEMCPY(buffer, seq, seqSz);

    return idx + seqSz;
}


/* Make an x509 Certificate v3 any key type from cert input, write to buffer */
static int MakeAnyCert(Cert* cert, byte* derBuffer, word32 derSz,
                       RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng,
                       const byte* ntruKey, word16 ntruSz)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    DerCert* der;
#else
    DerCert der[1];
#endif

    cert->keyType = eccKey ? ECC_KEY : (rsaKey ? RSA_KEY : NTRU_KEY);

#ifdef WOLFSSL_SMALL_STACK
    der = (DerCert*)XMALLOC(sizeof(DerCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL)
        return MEMORY_E;
#endif

    ret = EncodeCert(cert, der, rsaKey, eccKey, rng, ntruKey, ntruSz);
    if (ret == 0) {
        if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
            ret = BUFFER_E;
        else
            ret = cert->bodySz = WriteCertBody(der, derBuffer);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


/* Make an x509 Certificate v3 RSA or ECC from cert input, write to buffer */
int wc_MakeCert(Cert* cert, byte* derBuffer, word32 derSz, RsaKey* rsaKey,
             ecc_key* eccKey, WC_RNG* rng)
{
    return MakeAnyCert(cert, derBuffer, derSz, rsaKey, eccKey, rng, NULL, 0);
}


#ifdef HAVE_NTRU

int wc_MakeNtruCert(Cert* cert, byte* derBuffer, word32 derSz,
                  const byte* ntruKey, word16 keySz, WC_RNG* rng)
{
    return MakeAnyCert(cert, derBuffer, derSz, NULL, NULL, rng, ntruKey, keySz);
}

#endif /* HAVE_NTRU */


#ifdef WOLFSSL_CERT_REQ

static int SetReqAttrib(byte* output, char* pw, int extSz)
{
    static const byte cpOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                         0x09, 0x07 };
    static const byte erOid[] =
        { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                         0x09, 0x0e };

    int sz      = 0; /* overall size */
    int cpSz    = 0; /* Challenge Password section size */
    int cpSeqSz = 0;
    int cpSetSz = 0;
    int cpStrSz = 0;
    int pwSz    = 0;
    int erSz    = 0; /* Extension Request section size */
    int erSeqSz = 0;
    int erSetSz = 0;
    byte cpSeq[MAX_SEQ_SZ];
    byte cpSet[MAX_SET_SZ];
    byte cpStr[MAX_PRSTR_SZ];
    byte erSeq[MAX_SEQ_SZ];
    byte erSet[MAX_SET_SZ];

    output[0] = 0xa0;
    sz++;

    if (pw && pw[0]) {
        pwSz = (int)XSTRLEN(pw);
        cpStrSz = SetUTF8String(pwSz, cpStr);
        cpSetSz = SetSet(cpStrSz + pwSz, cpSet);
        cpSeqSz = SetSequence(sizeof(cpOid) + cpSetSz + cpStrSz + pwSz, cpSeq);
        cpSz = cpSeqSz + sizeof(cpOid) + cpSetSz + cpStrSz + pwSz;
    }

    if (extSz) {
        erSetSz = SetSet(extSz, erSet);
        erSeqSz = SetSequence(erSetSz + sizeof(erOid) + extSz, erSeq);
        erSz = extSz + erSetSz + erSeqSz + sizeof(erOid);
    }

    /* Put the pieces together. */
    sz += SetLength(cpSz + erSz, &output[sz]);

    if (cpSz) {
        XMEMCPY(&output[sz], cpSeq, cpSeqSz);
        sz += cpSeqSz;
        XMEMCPY(&output[sz], cpOid, sizeof(cpOid));
        sz += sizeof(cpOid);
        XMEMCPY(&output[sz], cpSet, cpSetSz);
        sz += cpSetSz;
        XMEMCPY(&output[sz], cpStr, cpStrSz);
        sz += cpStrSz;
        XMEMCPY(&output[sz], pw, pwSz);
        sz += pwSz;
    }

    if (erSz) {
        XMEMCPY(&output[sz], erSeq, erSeqSz);
        sz += erSeqSz;
        XMEMCPY(&output[sz], erOid, sizeof(erOid));
        sz += sizeof(erOid);
        XMEMCPY(&output[sz], erSet, erSetSz);
        sz += erSetSz;
        /* The actual extension data will be tacked onto the output later. */
    }

    return sz;
}


/* encode info from cert into DER encoded format */
static int EncodeCertReq(Cert* cert, DerCert* der,
                         RsaKey* rsaKey, ecc_key* eccKey)
{
    (void)eccKey;

    if (cert == NULL || der == NULL)
        return BAD_FUNC_ARG;

    /* init */
    XMEMSET(der, 0, sizeof(DerCert));

    /* version */
    der->versionSz = SetMyVersion(cert->version, der->version, FALSE);

    /* subject name */
    der->subjectSz = SetName(der->subject, sizeof(der->subject), &cert->subject);
    if (der->subjectSz <= 0)
        return SUBJECT_E;

    /* public key */
    if (cert->keyType == RSA_KEY) {
        if (rsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey,
                                           sizeof(der->publicKey), 1);
        if (der->publicKeySz <= 0)
            return PUBLIC_KEY_E;
    }

#ifdef HAVE_ECC
    if (cert->keyType == ECC_KEY) {
        if (eccKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey, 1);
        if (der->publicKeySz <= 0)
            return PUBLIC_KEY_E;
    }
#endif /* HAVE_ECC */

    /* set the extensions */
    der->extensionsSz = 0;

    /* CA */
    if (cert->isCA) {
        der->caSz = SetCa(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
    else
        der->caSz = 0;

#ifdef WOLFSSL_CERT_EXT
    /* SKID */
    if (cert->skidSz) {
        /* check the provided SKID size */
        if (cert->skidSz > (int)sizeof(der->skid))
            return SKID_E;

        der->skidSz = SetSKID(der->skid, sizeof(der->skid),
                              cert->skid, cert->skidSz);
        if (der->skidSz <= 0)
            return SKID_E;

        der->extensionsSz += der->skidSz;
    }
    else
        der->skidSz = 0;

    /* Key Usage */
    if (cert->keyUsage != 0){
        der->keyUsageSz = SetKeyUsage(der->keyUsage, sizeof(der->keyUsage),
                                      cert->keyUsage);
        if (der->keyUsageSz <= 0)
            return KEYUSAGE_E;

        der->extensionsSz += der->keyUsageSz;
    }
    else
        der->keyUsageSz = 0;
#endif /* WOLFSSL_CERT_EXT */

    /* put extensions */
    if (der->extensionsSz > 0) {
        int ret;

        /* put the start of sequence (ID, Size) */
        der->extensionsSz = SetSequence(der->extensionsSz, der->extensions);
        if (der->extensionsSz <= 0)
            return EXTENSIONS_E;

        /* put CA */
        if (der->caSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->ca, der->caSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

#ifdef WOLFSSL_CERT_EXT
        /* put SKID */
        if (der->skidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->skid, der->skidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put AKID */
        if (der->akidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->akid, der->akidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put KeyUsage */
        if (der->keyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->keyUsage, der->keyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

#endif /* WOLFSSL_CERT_EXT */
    }

    der->attribSz = SetReqAttrib(der->attrib,
                                 cert->challengePw, der->extensionsSz);
    if (der->attribSz <= 0)
        return REQ_ATTRIBUTE_E;

    der->total = der->versionSz + der->subjectSz + der->publicKeySz +
        der->extensionsSz + der->attribSz;

    return 0;
}


/* write DER encoded cert req to buffer, size already checked */
static int WriteCertReqBody(DerCert* der, byte* buffer)
{
    int idx;

    /* signed part header */
    idx = SetSequence(der->total, buffer);
    /* version */
    XMEMCPY(buffer + idx, der->version, der->versionSz);
    idx += der->versionSz;
    /* subject */
    XMEMCPY(buffer + idx, der->subject, der->subjectSz);
    idx += der->subjectSz;
    /* public key */
    XMEMCPY(buffer + idx, der->publicKey, der->publicKeySz);
    idx += der->publicKeySz;
    /* attributes */
    XMEMCPY(buffer + idx, der->attrib, der->attribSz);
    idx += der->attribSz;
    /* extensions */
    if (der->extensionsSz) {
        XMEMCPY(buffer + idx, der->extensions, min(der->extensionsSz,
                                                   sizeof(der->extensions)));
        idx += der->extensionsSz;
    }

    return idx;
}


int wc_MakeCertReq(Cert* cert, byte* derBuffer, word32 derSz,
                RsaKey* rsaKey, ecc_key* eccKey)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    DerCert* der;
#else
    DerCert der[1];
#endif

    cert->keyType = eccKey ? ECC_KEY : RSA_KEY;

#ifdef WOLFSSL_SMALL_STACK
    der = (DerCert*)XMALLOC(sizeof(DerCert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL)
        return MEMORY_E;
#endif

    ret = EncodeCertReq(cert, der, rsaKey, eccKey);

    if (ret == 0) {
        if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
            ret = BUFFER_E;
        else
            ret = cert->bodySz = WriteCertReqBody(der, derBuffer);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif /* WOLFSSL_CERT_REQ */


int wc_SignCert(int requestSz, int sType, byte* buffer, word32 buffSz,
             RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng)
{
    int sigSz;
#ifdef WOLFSSL_SMALL_STACK
    byte* sig;
#else
    byte sig[MAX_ENCODED_SIG_SZ];
#endif

    if (requestSz < 0)
        return requestSz;

#ifdef WOLFSSL_SMALL_STACK
    sig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig == NULL)
        return MEMORY_E;
#endif

    sigSz = MakeSignature(buffer, requestSz, sig, MAX_ENCODED_SIG_SZ, rsaKey,
                          eccKey, rng, sType);

    if (sigSz >= 0) {
        if (requestSz + MAX_SEQ_SZ * 2 + sigSz > (int)buffSz)
            sigSz = BUFFER_E;
        else
            sigSz = AddSignature(buffer, requestSz, sig, sigSz, sType);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return sigSz;
}


int wc_MakeSelfCert(Cert* cert, byte* buffer, word32 buffSz,
                    RsaKey* key, WC_RNG* rng)
{
    int ret;

    ret = wc_MakeCert(cert, buffer, buffSz, key, NULL, rng);
    if (ret < 0)
        return ret;

    return wc_SignCert(cert->bodySz, cert->sigType,
                       buffer, buffSz, key, NULL, rng);
}


#ifdef WOLFSSL_CERT_EXT

/* Set KID from RSA or ECC public key */
static int SetKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey, ecc_key *eckey,
                                 byte *ntruKey, word16 ntruKeySz, int kid_type)
{
    byte    *buffer;
    int     bufferSz, ret;

#ifndef HAVE_NTRU
    (void)ntruKeySz;
#endif

    if (cert == NULL || (rsakey == NULL && eckey == NULL && ntruKey == NULL) ||
        (rsakey != NULL && eckey != NULL) ||
        (rsakey != NULL && ntruKey != NULL) ||
        (ntruKey != NULL && eckey != NULL) ||
        (kid_type != SKID_TYPE && kid_type != AKID_TYPE))
        return BAD_FUNC_ARG;

    buffer = (byte *)XMALLOC(MAX_PUBLIC_KEY_SZ, cert->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (buffer == NULL)
        return MEMORY_E;

    /* RSA public key */
    if (rsakey != NULL)
        bufferSz = SetRsaPublicKey(buffer, rsakey, MAX_PUBLIC_KEY_SZ, 0);
#ifdef HAVE_ECC
    /* ECC public key */
    else if (eckey != NULL)
        bufferSz = SetEccPublicKey(buffer, eckey, 0);
#endif /* HAVE_ECC */
#ifdef HAVE_NTRU
    /* NTRU public key */
    else if (ntruKey != NULL) {
        bufferSz = MAX_PUBLIC_KEY_SZ;
        ret = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
                        ntruKeySz, ntruKey, (word16 *)(&bufferSz), buffer);
        if (ret != NTRU_OK)
            bufferSz = -1;
    }
#endif
    else
        bufferSz = -1;

    if (bufferSz <= 0) {
        XFREE(buffer, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return PUBLIC_KEY_E;
    }

    /* Compute SKID by hashing public key */
#ifdef NO_SHA
    if (kid_type == SKID_TYPE) {
        ret = wc_Sha256Hash(buffer, bufferSz, cert->skid);
        cert->skidSz = SHA256_DIGEST_SIZE;
    }
    else if (kid_type == AKID_TYPE) {
        ret = wc_Sha256Hash(buffer, bufferSz, cert->akid);
        cert->akidSz = SHA256_DIGEST_SIZE;
    }
    else
        ret = BAD_FUNC_ARG;
#else /* NO_SHA */
    if (kid_type == SKID_TYPE) {
        ret = wc_ShaHash(buffer, bufferSz, cert->skid);
        cert->skidSz = SHA_DIGEST_SIZE;
    }
    else if (kid_type == AKID_TYPE) {
        ret = wc_ShaHash(buffer, bufferSz, cert->akid);
        cert->akidSz = SHA_DIGEST_SIZE;
    }
    else
        ret = BAD_FUNC_ARG;
#endif /* NO_SHA */

    XFREE(buffer, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Set SKID from RSA or ECC public key */
int wc_SetSubjectKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey, ecc_key *eckey)
{
    return SetKeyIdFromPublicKey(cert, rsakey, eckey, NULL, 0, SKID_TYPE);
}

#ifdef HAVE_NTRU
/* Set SKID from NTRU public key */
int wc_SetSubjectKeyIdFromNtruPublicKey(Cert *cert,
                                        byte *ntruKey, word16 ntruKeySz)
{
    return SetKeyIdFromPublicKey(cert, NULL,NULL,ntruKey, ntruKeySz, SKID_TYPE);
}
#endif

/* Set SKID from RSA or ECC public key */
int wc_SetAuthKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey, ecc_key *eckey)
{
    return SetKeyIdFromPublicKey(cert, rsakey, eckey, NULL, 0, AKID_TYPE);
}


#ifndef NO_FILESYSTEM

/* Set SKID from public key file in PEM */
int wc_SetSubjectKeyId(Cert *cert, const char* file)
{
    int     ret, derSz;
    byte*   der;
    word32  idx;
    RsaKey  *rsakey = NULL;
    ecc_key *eckey = NULL;

    if (cert == NULL || file == NULL)
        return BAD_FUNC_ARG;

    der = (byte*)XMALLOC(MAX_PUBLIC_KEY_SZ, cert->heap, DYNAMIC_TYPE_CERT);
    if (der == NULL) {
        WOLFSSL_MSG("wc_SetSubjectKeyId memory Problem");
        return MEMORY_E;
    }

    derSz = wolfSSL_PemPubKeyToDer(file, der, MAX_PUBLIC_KEY_SZ);
    if (derSz <= 0)
    {
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return derSz;
    }

    /* Load PubKey in internal structure */
    rsakey = (RsaKey*) XMALLOC(sizeof(RsaKey), cert->heap, DYNAMIC_TYPE_RSA);
    if (rsakey == NULL) {
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return MEMORY_E;
    }

    if (wc_InitRsaKey(rsakey, cert->heap) != 0) {
        WOLFSSL_MSG("wc_InitRsaKey failure");
        XFREE(rsakey, cert->heap, DYNAMIC_TYPE_RSA);
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return MEMORY_E;
    }

    idx = 0;
    ret = wc_RsaPublicKeyDecode(der, &idx, rsakey, derSz);
    if (ret != 0) {
        WOLFSSL_MSG("wc_RsaPublicKeyDecode failed");
        wc_FreeRsaKey(rsakey);
        XFREE(rsakey, cert->heap, DYNAMIC_TYPE_RSA);
        rsakey = NULL;
#ifdef HAVE_ECC
        /* Check to load ecc public key */
        eckey = (ecc_key*) XMALLOC(sizeof(ecc_key), cert->heap,
                                                              DYNAMIC_TYPE_ECC);
        if (eckey == NULL) {
            XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
            return MEMORY_E;
        }

        if (wc_ecc_init(eckey) != 0) {
            WOLFSSL_MSG("wc_ecc_init failure");
            wc_ecc_free(eckey);
            XFREE(eckey, cert->heap, DYNAMIC_TYPE_ECC);
            XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
            return MEMORY_E;
        }

        idx = 0;
        ret = wc_EccPublicKeyDecode(der, &idx, eckey, derSz);
        if (ret != 0) {
            WOLFSSL_MSG("wc_EccPublicKeyDecode failed");
            XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
            wc_ecc_free(eckey);
            return PUBLIC_KEY_E;
        }
#else
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return PUBLIC_KEY_E;
#endif /* HAVE_ECC */
    }

    XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);

    ret = wc_SetSubjectKeyIdFromPublicKey(cert, rsakey, eckey);

    wc_FreeRsaKey(rsakey);
    XFREE(rsakey, cert->heap, DYNAMIC_TYPE_RSA);
#ifdef HAVE_ECC
    wc_ecc_free(eckey);
    XFREE(eckey, cert->heap, DYNAMIC_TYPE_ECC);
#endif
    return ret;
}

#endif /* NO_FILESYSTEM */

/* Set AKID from certificate contains in buffer (DER encoded) */
int wc_SetAuthKeyIdFromCert(Cert *cert, const byte *der, int derSz)
{
    int ret;

#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* decoded;
#else
    DecodedCert decoded[1];
#endif

    if (cert == NULL || der == NULL || derSz <= 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert),
                                    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return MEMORY_E;
#endif

    /* decode certificate and get SKID that will be AKID of current cert */
    InitDecodedCert(decoded, (byte*)der, derSz, 0);
    ret = ParseCert(decoded, CERT_TYPE, NO_VERIFY, 0);
    if (ret != 0) {
        FreeDecodedCert(decoded);
        return ret;
    }

    /* Subject Key Id not found !! */
    if (decoded->extSubjKeyIdSet == 0) {
        FreeDecodedCert(decoded);
        return ASN_NO_SKID;
    }

    /* SKID invalid size */
    if (sizeof(cert->akid) < sizeof(decoded->extSubjKeyId)) {
        FreeDecodedCert(decoded);
        return MEMORY_E;
    }

    /* Put the SKID of CA to AKID of certificate */
    XMEMCPY(cert->akid, decoded->extSubjKeyId, KEYID_SIZE);
    cert->akidSz = KEYID_SIZE;

    FreeDecodedCert(decoded);
    return 0;
}


#ifndef NO_FILESYSTEM

/* Set AKID from certificate file in PEM */
int wc_SetAuthKeyId(Cert *cert, const char* file)
{
    int         ret;
    int         derSz;
    byte*       der;

    if (cert == NULL || file == NULL)
        return BAD_FUNC_ARG;

    der = (byte*)XMALLOC(EIGHTK_BUF, cert->heap, DYNAMIC_TYPE_CERT);
    if (der == NULL) {
        WOLFSSL_MSG("wc_SetAuthKeyId OOF Problem");
        return MEMORY_E;
    }

    derSz = wolfSSL_PemCertToDer(file, der, EIGHTK_BUF);
    if (derSz <= 0)
    {
        XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);
        return derSz;
    }

    ret = wc_SetAuthKeyIdFromCert(cert, der, derSz);
    XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);

    return ret;
}

#endif /* NO_FILESYSTEM */

/* Set KeyUsage from human readable string */
int wc_SetKeyUsage(Cert *cert, const char *value)
{
    char *token, *str, *ptr;
    word32 len;

    if (cert == NULL || value == NULL)
        return BAD_FUNC_ARG;

    cert->keyUsage = 0;

    str = (char *)XMALLOC(XSTRLEN(value)+1, cert->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (str == NULL)
        return MEMORY_E;

    XMEMSET(str, 0, XSTRLEN(value)+1);
    XSTRNCPY(str, value, XSTRLEN(value));

    /* parse value, and set corresponding Key Usage value */
    token = XSTRTOK(str, ",", &ptr);
    while (token != NULL)
    {
        len = (word32)XSTRLEN(token);

        if (!XSTRNCASECMP(token, "digitalSignature", len))
            cert->keyUsage |= KEYUSE_DIGITAL_SIG;
        else if (!XSTRNCASECMP(token, "nonRepudiation", len) ||
                 !XSTRNCASECMP(token, "contentCommitment", len))
            cert->keyUsage |= KEYUSE_CONTENT_COMMIT;
        else if (!XSTRNCASECMP(token, "keyEncipherment", len))
            cert->keyUsage |= KEYUSE_KEY_ENCIPHER;
        else if (!XSTRNCASECMP(token, "dataEncipherment", len))
            cert->keyUsage |= KEYUSE_DATA_ENCIPHER;
        else if (!XSTRNCASECMP(token, "keyAgreement", len))
            cert->keyUsage |= KEYUSE_KEY_AGREE;
        else if (!XSTRNCASECMP(token, "keyCertSign", len))
            cert->keyUsage |= KEYUSE_KEY_CERT_SIGN;
        else if (!XSTRNCASECMP(token, "cRLSign", len))
            cert->keyUsage |= KEYUSE_CRL_SIGN;
        else if (!XSTRNCASECMP(token, "encipherOnly", len))
            cert->keyUsage |= KEYUSE_ENCIPHER_ONLY;
        else if (!XSTRNCASECMP(token, "decipherOnly", len))
            cert->keyUsage |= KEYUSE_DECIPHER_ONLY;
        else
            return KEYUSAGE_E;

        token = XSTRTOK(NULL, ",", &ptr);
    }

    XFREE(str, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}
#endif /* WOLFSSL_CERT_EXT */


#ifdef WOLFSSL_ALT_NAMES

/* Set Alt Names from der cert, return 0 on success */
static int SetAltNamesFromCert(Cert* cert, const byte* der, int derSz)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* decoded;
#else
    DecodedCert decoded[1];
#endif

    if (derSz < 0)
        return derSz;

#ifdef WOLFSSL_SMALL_STACK
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(decoded, (byte*)der, derSz, 0);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else if (decoded->extensions) {
        byte   b;
        int    length;
        word32 maxExtensionsIdx;

        decoded->srcIdx = decoded->extensionsIdx;
        b = decoded->source[decoded->srcIdx++];

        if (b != ASN_EXTENSIONS) {
            ret = ASN_PARSE_E;
        }
        else if (GetLength(decoded->source, &decoded->srcIdx, &length,
                                                         decoded->maxIdx) < 0) {
            ret = ASN_PARSE_E;
        }
        else if (GetSequence(decoded->source, &decoded->srcIdx, &length,
                                                         decoded->maxIdx) < 0) {
            ret = ASN_PARSE_E;
        }
        else {
            maxExtensionsIdx = decoded->srcIdx + length;

            while (decoded->srcIdx < maxExtensionsIdx) {
                word32 oid;
                word32 startIdx = decoded->srcIdx;
                word32 tmpIdx;

                if (GetSequence(decoded->source, &decoded->srcIdx, &length,
                            decoded->maxIdx) < 0) {
                    ret = ASN_PARSE_E;
                    break;
                }

                tmpIdx = decoded->srcIdx;
                decoded->srcIdx = startIdx;

                if (GetAlgoId(decoded->source, &decoded->srcIdx, &oid,
                              oidCertExtType, decoded->maxIdx) < 0) {
                    ret = ASN_PARSE_E;
                    break;
                }

                if (oid == ALT_NAMES_OID) {
                    cert->altNamesSz = length + (tmpIdx - startIdx);

                    if (cert->altNamesSz < (int)sizeof(cert->altNames))
                        XMEMCPY(cert->altNames, &decoded->source[startIdx],
                                cert->altNamesSz);
                    else {
                        cert->altNamesSz = 0;
                        WOLFSSL_MSG("AltNames extensions too big");
                        ret = ALT_NAME_E;
                        break;
                    }
                }
                decoded->srcIdx = tmpIdx + length;
            }
        }
    }

    FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret < 0 ? ret : 0;
}


/* Set Dates from der cert, return 0 on success */
static int SetDatesFromCert(Cert* cert, const byte* der, int derSz)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* decoded;
#else
    DecodedCert decoded[1];
#endif

    WOLFSSL_ENTER("SetDatesFromCert");
    if (derSz < 0)
        return derSz;

#ifdef WOLFSSL_SMALL_STACK
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(decoded, (byte*)der, derSz, 0);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else if (decoded->beforeDate == NULL || decoded->afterDate == NULL) {
        WOLFSSL_MSG("Couldn't extract dates");
        ret = -1;
    }
    else if (decoded->beforeDateLen > MAX_DATE_SIZE ||
                                        decoded->afterDateLen > MAX_DATE_SIZE) {
        WOLFSSL_MSG("Bad date size");
        ret = -1;
    }
    else {
        XMEMCPY(cert->beforeDate, decoded->beforeDate, decoded->beforeDateLen);
        XMEMCPY(cert->afterDate,  decoded->afterDate,  decoded->afterDateLen);

        cert->beforeDateSz = decoded->beforeDateLen;
        cert->afterDateSz  = decoded->afterDateLen;
    }

    FreeDecodedCert(decoded);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret < 0 ? ret : 0;
}


#endif /* WOLFSSL_ALT_NAMES && !NO_RSA */


/* Set cn name from der buffer, return 0 on success */
static int SetNameFromCert(CertName* cn, const byte* der, int derSz)
{
    int ret, sz;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* decoded;
#else
    DecodedCert decoded[1];
#endif

    if (derSz < 0)
        return derSz;

#ifdef WOLFSSL_SMALL_STACK
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (decoded == NULL)
        return MEMORY_E;
#endif

    InitDecodedCert(decoded, (byte*)der, derSz, 0);
    ret = ParseCertRelative(decoded, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0) {
        WOLFSSL_MSG("ParseCertRelative error");
    }
    else {
        if (decoded->subjectCN) {
            sz = (decoded->subjectCNLen < CTC_NAME_SIZE) ? decoded->subjectCNLen
                                                         : CTC_NAME_SIZE - 1;
            strncpy(cn->commonName, decoded->subjectCN, CTC_NAME_SIZE);
            cn->commonName[sz] = 0;
            cn->commonNameEnc = decoded->subjectCNEnc;
        }
        if (decoded->subjectC) {
            sz = (decoded->subjectCLen < CTC_NAME_SIZE) ? decoded->subjectCLen
                                                        : CTC_NAME_SIZE - 1;
            strncpy(cn->country, decoded->subjectC, CTC_NAME_SIZE);
            cn->country[sz] = 0;
            cn->countryEnc = decoded->subjectCEnc;
        }
        if (decoded->subjectST) {
            sz = (decoded->subjectSTLen < CTC_NAME_SIZE) ? decoded->subjectSTLen
                                                         : CTC_NAME_SIZE - 1;
            strncpy(cn->state, decoded->subjectST, CTC_NAME_SIZE);
            cn->state[sz] = 0;
            cn->stateEnc = decoded->subjectSTEnc;
        }
        if (decoded->subjectL) {
            sz = (decoded->subjectLLen < CTC_NAME_SIZE) ? decoded->subjectLLen
                                                        : CTC_NAME_SIZE - 1;
            strncpy(cn->locality, decoded->subjectL, CTC_NAME_SIZE);
            cn->locality[sz] = 0;
            cn->localityEnc = decoded->subjectLEnc;
        }
        if (decoded->subjectO) {
            sz = (decoded->subjectOLen < CTC_NAME_SIZE) ? decoded->subjectOLen
                                                        : CTC_NAME_SIZE - 1;
            strncpy(cn->org, decoded->subjectO, CTC_NAME_SIZE);
            cn->org[sz] = 0;
            cn->orgEnc = decoded->subjectOEnc;
        }
        if (decoded->subjectOU) {
            sz = (decoded->subjectOULen < CTC_NAME_SIZE) ? decoded->subjectOULen
                                                         : CTC_NAME_SIZE - 1;
            strncpy(cn->unit, decoded->subjectOU, CTC_NAME_SIZE);
            cn->unit[sz] = 0;
            cn->unitEnc = decoded->subjectOUEnc;
        }
        if (decoded->subjectSN) {
            sz = (decoded->subjectSNLen < CTC_NAME_SIZE) ? decoded->subjectSNLen
                                                         : CTC_NAME_SIZE - 1;
            strncpy(cn->sur, decoded->subjectSN, CTC_NAME_SIZE);
            cn->sur[sz] = 0;
            cn->surEnc = decoded->subjectSNEnc;
        }
        if (decoded->subjectEmail) {
            sz = (decoded->subjectEmailLen < CTC_NAME_SIZE)
               ?  decoded->subjectEmailLen : CTC_NAME_SIZE - 1;
            strncpy(cn->email, decoded->subjectEmail, CTC_NAME_SIZE);
            cn->email[sz] = 0;
        }
    }

    FreeDecodedCert(decoded);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(decoded, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret < 0 ? ret : 0;
}


#ifndef NO_FILESYSTEM

/* Set cert issuer from issuerFile in PEM */
int wc_SetIssuer(Cert* cert, const char* issuerFile)
{
    int         ret;
    int         derSz;
    byte*       der = (byte*)XMALLOC(EIGHTK_BUF, cert->heap, DYNAMIC_TYPE_CERT);

    if (der == NULL) {
        WOLFSSL_MSG("wc_SetIssuer OOF Problem");
        return MEMORY_E;
    }
    derSz = wolfSSL_PemCertToDer(issuerFile, der, EIGHTK_BUF);
    cert->selfSigned = 0;
    ret = SetNameFromCert(&cert->issuer, der, derSz);
    XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);

    return ret;
}


/* Set cert subject from subjectFile in PEM */
int wc_SetSubject(Cert* cert, const char* subjectFile)
{
    int         ret;
    int         derSz;
    byte*       der = (byte*)XMALLOC(EIGHTK_BUF, cert->heap, DYNAMIC_TYPE_CERT);

    if (der == NULL) {
        WOLFSSL_MSG("wc_SetSubject OOF Problem");
        return MEMORY_E;
    }
    derSz = wolfSSL_PemCertToDer(subjectFile, der, EIGHTK_BUF);
    ret = SetNameFromCert(&cert->subject, der, derSz);
    XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);

    return ret;
}


#ifdef WOLFSSL_ALT_NAMES

/* Set atl names from file in PEM */
int wc_SetAltNames(Cert* cert, const char* file)
{
    int         ret;
    int         derSz;
    byte*       der = (byte*)XMALLOC(EIGHTK_BUF, cert->heap, DYNAMIC_TYPE_CERT);

    if (der == NULL) {
        WOLFSSL_MSG("wc_SetAltNames OOF Problem");
        return MEMORY_E;
    }
    derSz = wolfSSL_PemCertToDer(file, der, EIGHTK_BUF);
    ret = SetAltNamesFromCert(cert, der, derSz);
    XFREE(der, cert->heap, DYNAMIC_TYPE_CERT);

    return ret;
}

#endif /* WOLFSSL_ALT_NAMES */

#endif /* NO_FILESYSTEM */

/* Set cert issuer from DER buffer */
int wc_SetIssuerBuffer(Cert* cert, const byte* der, int derSz)
{
    cert->selfSigned = 0;
    return SetNameFromCert(&cert->issuer, der, derSz);
}


/* Set cert subject from DER buffer */
int wc_SetSubjectBuffer(Cert* cert, const byte* der, int derSz)
{
    return SetNameFromCert(&cert->subject, der, derSz);
}


#ifdef WOLFSSL_ALT_NAMES

/* Set cert alt names from DER buffer */
int wc_SetAltNamesBuffer(Cert* cert, const byte* der, int derSz)
{
    return SetAltNamesFromCert(cert, der, derSz);
}

/* Set cert dates from DER buffer */
int wc_SetDatesBuffer(Cert* cert, const byte* der, int derSz)
{
    return SetDatesFromCert(cert, der, derSz);
}

#endif /* WOLFSSL_ALT_NAMES */

#endif /* WOLFSSL_CERT_GEN */


#ifdef HAVE_ECC

/* Der Encode r & s ints into out, outLen is (in/out) size */
int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    word32 rSz;                           /* encoding size */
    word32 sSz;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */

    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    int rLeadingZero = mp_leading_bit(r);
    int sLeadingZero = mp_leading_bit(s);
    int rLen = mp_unsigned_bin_size(r);   /* big int size */
    int sLen = mp_unsigned_bin_size(s);
    int err;

    if (*outLen < (rLen + rLeadingZero + sLen + sLeadingZero +
                   headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return BAD_FUNC_ARG;

    idx = SetSequence(rLen+rLeadingZero+sLen+sLeadingZero+headerSz, out);

    /* store r */
    out[idx++] = ASN_INTEGER;
    rSz = SetLength(rLen + rLeadingZero, &out[idx]);
    idx += rSz;
    if (rLeadingZero)
        out[idx++] = 0;
    err = mp_to_unsigned_bin(r, &out[idx]);
    if (err != MP_OKAY) return err;
    idx += rLen;

    /* store s */
    out[idx++] = ASN_INTEGER;
    sSz = SetLength(sLen + sLeadingZero, &out[idx]);
    idx += sSz;
    if (sLeadingZero)
        out[idx++] = 0;
    err = mp_to_unsigned_bin(s, &out[idx]);
    if (err != MP_OKAY) return err;
    idx += sLen;

    *outLen = idx;

    return 0;
}


/* Der Decode ECC-DSA Signature, r & s stored as big ints */
int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0)
        return ASN_ECC_KEY_E;

    if ((word32)len > (sigLen - idx))
        return ASN_ECC_KEY_E;

    if (GetInt(r, sig, &idx, sigLen) < 0)
        return ASN_ECC_KEY_E;

    if (GetInt(s, sig, &idx, sigLen) < 0)
        return ASN_ECC_KEY_E;

    return 0;
}


int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx, ecc_key* key,
                        word32 inSz)
{
    word32 oid = 0;
    int    version, length;
    int    privSz, pubSz;
    byte   b;
    int    ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* priv;
    byte* pub;
#else
    byte priv[ECC_MAXSIZE+1];
    byte pub[2*(ECC_MAXSIZE+1)]; /* public key has two parts plus header */
#endif

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    b = input[*inOutIdx];
    *inOutIdx += 1;

    /* priv type */
    if (b != 4 && b != 6 && b != 7)
        return ASN_PARSE_E;

    if (GetLength(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (length > ECC_MAXSIZE)
        return BUFFER_E;

#ifdef WOLFSSL_SMALL_STACK
    priv = (byte*)XMALLOC(ECC_MAXSIZE+1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv == NULL)
        return MEMORY_E;

    pub = (byte*)XMALLOC(2*(ECC_MAXSIZE+1), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL) {
        XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* priv key */
    privSz = length;
    XMEMCPY(priv, &input[*inOutIdx], privSz);
    *inOutIdx += length;

    /* prefix 0, may have */
    b = input[*inOutIdx];
    if (b == ECC_PREFIX_0) {
        *inOutIdx += 1;

        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            ret = ASN_PARSE_E;
        else {
            /* object id */
            b = input[*inOutIdx];
            *inOutIdx += 1;

            if (b != ASN_OBJECT_ID) {
                ret = ASN_OBJECT_ID_E;
            }
            else if (GetLength(input, inOutIdx, &length, inSz) < 0) {
                ret = ASN_PARSE_E;
            }
            else {
                while(length--) {
                    oid += input[*inOutIdx];
                    *inOutIdx += 1;
                }
                if (CheckCurve(oid) < 0)
                    ret = ECC_CURVE_OID_E;
            }
        }
    }

    if (ret == 0) {
        /* prefix 1 */
        b = input[*inOutIdx];
        *inOutIdx += 1;

        if (b != ECC_PREFIX_1) {
            ret = ASN_ECC_KEY_E;
        }
        else if (GetLength(input, inOutIdx, &length, inSz) < 0) {
            ret = ASN_PARSE_E;
        }
        else {
            /* key header */
            b = input[*inOutIdx];
            *inOutIdx += 1;

            if (b != ASN_BIT_STRING) {
                ret = ASN_BITSTR_E;
            }
            else if (GetLength(input, inOutIdx, &length, inSz) < 0) {
                ret = ASN_PARSE_E;
            }
            else if (length <= 0) {
                /* pubkey needs some size */
                ret = ASN_INPUT_E;
            }
            else {
                b = input[*inOutIdx];
                *inOutIdx += 1;

                if (b != 0x00) {
                    ret = ASN_EXPECT_0_E;
                }
                else {
                    /* pub key */
                    pubSz = length - 1;  /* null prefix */
                    if (pubSz < 2*(ECC_MAXSIZE+1)) {
                        XMEMCPY(pub, &input[*inOutIdx], pubSz);
                        *inOutIdx += length;
                        ret = wc_ecc_import_private_key(priv, privSz, pub, pubSz,
                                                     key);
                    } else
                        ret = BUFFER_E;
                }
            }
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(priv, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
                          ecc_key* key, word32 inSz)
{
    int    length;
    int    ret = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#if defined(OPENSSL_EXTRA) || defined(ECC_DECODE_EXTRA)
    {
        byte b = input[*inOutIdx];
        if (b != ASN_INTEGER) {
            /* not from decoded cert, will have algo id, skip past */
            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                return ASN_PARSE_E;

            b = input[(*inOutIdx)++];
            if (b != ASN_OBJECT_ID)
                return ASN_OBJECT_ID_E;

            if (GetLength(input, inOutIdx, &length, inSz) < 0)
                return ASN_PARSE_E;

            *inOutIdx += length;   /* skip past */

            /* ecc params information */
            b = input[(*inOutIdx)++];
            if (b != ASN_OBJECT_ID)
                return ASN_OBJECT_ID_E;

            if (GetLength(input, inOutIdx, &length, inSz) < 0)
                return ASN_PARSE_E;

            *inOutIdx += length;   /* skip past */

            /* key header */
            b = input[*inOutIdx];
            *inOutIdx += 1;

            if (b != ASN_BIT_STRING)
                ret = ASN_BITSTR_E;
            else if (GetLength(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
            else {
                b = input[*inOutIdx];
                *inOutIdx += 1;

                if (b != 0x00)
                    ret = ASN_EXPECT_0_E;
            }
        }
    }  /* openssl var block */
#endif /* OPENSSL_EXTRA */

    if (wc_ecc_import_x963(input+*inOutIdx, inSz - *inOutIdx, key) != 0)
        return ASN_ECC_KEY_E;

    return ret;
}


#ifdef WOLFSSL_KEY_GEN

/* Write a Private ecc key to DER format, length on success else < 0 */
int wc_EccKeyToDer(ecc_key* key, byte* output, word32 inLen)
{
    byte   curve[MAX_ALGO_SZ+2];
    byte   ver[MAX_VERSION_SZ];
    byte   seq[MAX_SEQ_SZ];
    byte   *prv, *pub;
    int    ret, totalSz, curveSz, verSz;
    int    privHdrSz  = ASN_ECC_HEADER_SZ;
    int    pubHdrSz   = ASN_ECC_CONTEXT_SZ + ASN_ECC_HEADER_SZ;

    word32 idx = 0, prvidx = 0, pubidx = 0, curveidx = 0;
    word32 seqSz, privSz, pubSz = ECC_BUFSIZE;

    if (key == NULL || output == NULL || inLen == 0)
        return BAD_FUNC_ARG;

    /* curve */
    curve[curveidx++] = ECC_PREFIX_0;
    curveidx++ /* to put the size after computation */;
    curveSz = SetCurve(key, curve+curveidx);
    if (curveSz < 0)
        return curveSz;
    /* set computed size */
    curve[1] = (byte)curveSz;
    curveidx += curveSz;

    /* private */
    privSz = key->dp->size;
    prv = (byte*)XMALLOC(privSz + privHdrSz + MAX_SEQ_SZ,
                         key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (prv == NULL) {
        return MEMORY_E;
    }
    prv[prvidx++] = ASN_OCTET_STRING;
    prv[prvidx++] = (byte)key->dp->size;
    ret = wc_ecc_export_private_only(key, prv + prvidx, &privSz);
    if (ret < 0) {
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    prvidx += privSz;

    /* public */
    ret = wc_ecc_export_x963(key, NULL, &pubSz);
    if (ret != LENGTH_ONLY_E) {
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    pub = (byte*)XMALLOC(pubSz + pubHdrSz + MAX_SEQ_SZ,
                         key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL) {
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    pub[pubidx++] = ECC_PREFIX_1;
    if (pubSz > 128) /* leading zero + extra size byte */
        pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 2, pub+pubidx);
    else /* leading zero */
        pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 1, pub+pubidx);
    pub[pubidx++] = ASN_BIT_STRING;
    pubidx += SetLength(pubSz + 1, pub+pubidx);
    pub[pubidx++] = (byte)0; /* leading zero */
    ret = wc_ecc_export_x963(key, pub + pubidx, &pubSz);
    if (ret != 0) {
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    pubidx += pubSz;

    /* make headers */
    verSz = SetMyVersion(1, ver, FALSE);
    seqSz = SetSequence(verSz + prvidx + pubidx + curveidx, seq);

    totalSz = prvidx + pubidx + curveidx + verSz + seqSz;
    if (totalSz > (int)inLen) {
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BAD_FUNC_ARG;
    }

    /* write out */
    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx = seqSz;

    /* ver */
    XMEMCPY(output + idx, ver, verSz);
    idx += verSz;

    /* private */
    XMEMCPY(output + idx, prv, prvidx);
    idx += prvidx;
    XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    /* curve */
    XMEMCPY(output + idx, curve, curveidx);
    idx += curveidx;

    /* public */
    XMEMCPY(output + idx, pub, pubidx);
    /* idx += pubidx;  not used after write, if more data remove comment */
    XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return totalSz;
}

#endif /* WOLFSSL_KEY_GEN */

#endif  /* HAVE_ECC */


#if defined(HAVE_OCSP) || defined(HAVE_CRL)

/* Get raw Date only, no processing, 0 on success */
static int GetBasicDate(const byte* source, word32* idx, byte* date,
                        byte* format, int maxIdx)
{
    int    length;

    WOLFSSL_ENTER("GetBasicDate");

    *format = source[*idx];
    *idx += 1;
    if (*format != ASN_UTC_TIME && *format != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    XMEMCPY(date, &source[*idx], length);
    *idx += length;

    return 0;
}

#endif


#ifdef HAVE_OCSP

static int GetEnumerated(const byte* input, word32* inOutIdx, int *value)
{
    word32 idx = *inOutIdx;
    word32 len;

    WOLFSSL_ENTER("GetEnumerated");

    *value = 0;

    if (input[idx++] != ASN_ENUMERATED)
        return ASN_PARSE_E;

    len = input[idx++];
    if (len > 4)
        return ASN_PARSE_E;

    while (len--) {
        *value  = *value << 8 | input[idx++];
    }

    *inOutIdx = idx;

    return *value;
}


static int DecodeSingleResponse(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex, prevIndex, oid;
    int length, wrapperSz;
    CertStatus* cs = resp->status;

    WOLFSSL_ENTER("DecodeSingleResponse");

    /* Outer wrapper of the SEQUENCE OF Single Responses. */
    if (GetSequence(source, &idx, &wrapperSz, size) < 0)
        return ASN_PARSE_E;

    prevIndex = idx;

    /* When making a request, we only request one status on one certificate
     * at a time. There should only be one SingleResponse */

    /* Wrapper around the Single Response */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* Wrapper around the CertID */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    /* Skip the hash algorithm */
    if (GetAlgoId(source, &idx, &oid, oidIgnoreType, size) < 0)
        return ASN_PARSE_E;
    /* Save reference to the hash of CN */
    if (source[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    resp->issuerHash = source + idx;
    idx += length;
    /* Save reference to the hash of the issuer public key */
    if (source[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    resp->issuerKeyHash = source + idx;
    idx += length;

    /* Get serial number */
    if (GetSerialNumber(source, &idx, cs->serial, &cs->serialSz, size) < 0)
        return ASN_PARSE_E;

    /* CertStatus */
    switch (source[idx++])
    {
        case (ASN_CONTEXT_SPECIFIC | CERT_GOOD):
            cs->status = CERT_GOOD;
            idx++;
            break;
        case (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | CERT_REVOKED):
            cs->status = CERT_REVOKED;
            if (GetLength(source, &idx, &length, size) < 0)
                return ASN_PARSE_E;
            idx += length;
            break;
        case (ASN_CONTEXT_SPECIFIC | CERT_UNKNOWN):
            cs->status = CERT_UNKNOWN;
            idx++;
            break;
        default:
            return ASN_PARSE_E;
    }

    if (GetBasicDate(source, &idx, cs->thisDate,
                                                &cs->thisDateFormat, size) < 0)
        return ASN_PARSE_E;
    if (!XVALIDATE_DATE(cs->thisDate, cs->thisDateFormat, BEFORE))
        return ASN_BEFORE_DATE_E;

    /* The following items are optional. Only check for them if there is more
     * unprocessed data in the singleResponse wrapper. */

    if (((int)(idx - prevIndex) < wrapperSz) &&
        (source[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)))
    {
        idx++;
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        if (GetBasicDate(source, &idx, cs->nextDate,
                                                &cs->nextDateFormat, size) < 0)
            return ASN_PARSE_E;
        if (!XVALIDATE_DATE(cs->nextDate, cs->nextDateFormat, AFTER))
            return ASN_AFTER_DATE_E;
    }
    if (((int)(idx - prevIndex) < wrapperSz) &&
        (source[idx] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)))
    {
        idx++;
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    *ioIndex = idx;

    return 0;
}

static int DecodeOcspRespExtensions(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 sz)
{
    word32 idx = *ioIndex;
    int length;
    int ext_bound; /* boundary index for the sequence of extensions */
    word32 oid;

    WOLFSSL_ENTER("DecodeOcspRespExtensions");

    if (source[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
        return ASN_PARSE_E;

    if (GetLength(source, &idx, &length, sz) < 0) return ASN_PARSE_E;

    if (GetSequence(source, &idx, &length, sz) < 0) return ASN_PARSE_E;

    ext_bound = idx + length;

    while (idx < (word32)ext_bound) {
        if (GetSequence(source, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if (GetObjectId(source, &idx, &oid, oidOcspType, sz) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ASN_PARSE_E;
        }

        /* check for critical flag */
        if (source[idx] == ASN_BOOLEAN) {
            WOLFSSL_MSG("\tfound optional critical flag, moving past");
            idx += (ASN_BOOL_SIZE + 1);
        }

        /* process the extension based on the OID */
        if (source[idx++] != ASN_OCTET_STRING) {
            WOLFSSL_MSG("\tfail: should be an OCTET STRING");
            return ASN_PARSE_E;
        }

        if (GetLength(source, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: extension data length");
            return ASN_PARSE_E;
        }

        if (oid == OCSP_NONCE_OID) {
            /* get data inside extra OCTET_STRING */
            if (source[idx++] != ASN_OCTET_STRING) {
                WOLFSSL_MSG("\tfail: should be an OCTET STRING");
                return ASN_PARSE_E;
            }

            if (GetLength(source, &idx, &length, sz) < 0) {
                WOLFSSL_MSG("\tfail: extension data length");
                return ASN_PARSE_E;
            }

            resp->nonce = source + idx;
            resp->nonceSz = length;
        }

        idx += length;
    }

    *ioIndex = idx;
    return 0;
}


static int DecodeResponseData(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex, prev_idx;
    int length;
    int version;
    word32 responderId = 0;

    WOLFSSL_ENTER("DecodeResponseData");

    resp->response = source + idx;
    prev_idx = idx;
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    resp->responseSz = length + idx - prev_idx;

    /* Get version. It is an EXPLICIT[0] DEFAULT(0) value. If this
     * item isn't an EXPLICIT[0], then set version to zero and move
     * onto the next item.
     */
    if (source[idx] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
    {
        idx += 2; /* Eat the value and length */
        if (GetMyVersion(source, &idx, &version) < 0)
            return ASN_PARSE_E;
    } else
        version = 0;

    responderId = source[idx++];
    if ((responderId == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) ||
        (responderId == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2)))
    {
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        idx += length;
    }
    else
        return ASN_PARSE_E;

    /* save pointer to the producedAt time */
    if (GetBasicDate(source, &idx, resp->producedDate,
                                        &resp->producedDateFormat, size) < 0)
        return ASN_PARSE_E;

    if (DecodeSingleResponse(source, &idx, resp, size) < 0)
        return ASN_PARSE_E;

    /*
     * Check the length of the ResponseData against the current index to
     * see if there are extensions, they are optional.
     */
    if (idx - prev_idx < resp->responseSz)
        if (DecodeOcspRespExtensions(source, &idx, resp, size) < 0)
            return ASN_PARSE_E;

    *ioIndex = idx;
    return 0;
}


static int DecodeCerts(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex;

    WOLFSSL_ENTER("DecodeCerts");

    if (source[idx++] == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC))
    {
        int length;

        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        if (GetSequence(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        resp->cert = source + idx;
        resp->certSz = length;

        idx += length;
    }
    *ioIndex = idx;
    return 0;
}

static int DecodeBasicOcspResponse(byte* source, word32* ioIndex,
                          OcspResponse* resp, word32 size, void* cm, void* heap)
{
    int length;
    word32 idx = *ioIndex;
    word32 end_index;
    int ret = -1;

    WOLFSSL_ENTER("DecodeBasicOcspResponse");

    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    if (idx + length > size)
        return ASN_INPUT_E;
    end_index = idx + length;

    if (DecodeResponseData(source, &idx, resp, size) < 0)
        return ASN_PARSE_E;

    /* Get the signature algorithm */
    if (GetAlgoId(source, &idx, &resp->sigOID, oidSigType, size) < 0)
        return ASN_PARSE_E;

    /* Obtain pointer to the start of the signature, and save the size */
    if (source[idx++] == ASN_BIT_STRING)
    {
        int sigLength = 0;
        if (GetLength(source, &idx, &sigLength, size) < 0)
            return ASN_PARSE_E;
        resp->sigSz = sigLength;
        resp->sig = source + idx;
        idx += sigLength;
    }

    /*
     * Check the length of the BasicOcspResponse against the current index to
     * see if there are certificates, they are optional.
     */
    if (idx < end_index)
    {
        DecodedCert cert;

        if (DecodeCerts(source, &idx, resp, size) < 0)
            return ASN_PARSE_E;

        InitDecodedCert(&cert, resp->cert, resp->certSz, heap);
        ret = ParseCertRelative(&cert, CERT_TYPE, VERIFY, cm);
        if (ret < 0)
            return ret;

        ret = ConfirmSignature(resp->response, resp->responseSz,
                            cert.publicKey, cert.pubKeySize, cert.keyOID,
                            resp->sig, resp->sigSz, resp->sigOID, NULL);
        FreeDecodedCert(&cert);

        if (ret == 0)
        {
            WOLFSSL_MSG("\tOCSP Confirm signature failed");
            return ASN_OCSP_CONFIRM_E;
        }
    }
    else {
        Signer* ca = GetCA(cm, resp->issuerKeyHash);

        if (!ca || !ConfirmSignature(resp->response, resp->responseSz,
                                     ca->publicKey, ca->pubKeySize, ca->keyOID,
                                  resp->sig, resp->sigSz, resp->sigOID, NULL)) {
            WOLFSSL_MSG("\tOCSP Confirm signature failed");
            return ASN_OCSP_CONFIRM_E;
        }
    }

    *ioIndex = idx;
    return 0;
}


void InitOcspResponse(OcspResponse* resp, CertStatus* status,
                                                    byte* source, word32 inSz)
{
    WOLFSSL_ENTER("InitOcspResponse");

    XMEMSET(status, 0, sizeof(CertStatus));
    XMEMSET(resp,   0, sizeof(OcspResponse));

    resp->responseStatus = -1;
    resp->status         = status;
    resp->source         = source;
    resp->maxIdx         = inSz;
}


int OcspResponseDecode(OcspResponse* resp, void* cm, void* heap)
{
    int length = 0;
    word32 idx = 0;
    byte* source = resp->source;
    word32 size = resp->maxIdx;
    word32 oid;

    WOLFSSL_ENTER("OcspResponseDecode");

    /* peel the outer SEQUENCE wrapper */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* First get the responseStatus, an ENUMERATED */
    if (GetEnumerated(source, &idx, &resp->responseStatus) < 0)
        return ASN_PARSE_E;

    if (resp->responseStatus != OCSP_SUCCESSFUL)
        return 0;

    /* Next is an EXPLICIT record called ResponseBytes, OPTIONAL */
    if (idx >= size)
        return ASN_INPUT_E;
    if (source[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC))
        return ASN_PARSE_E;
    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* Get the responseBytes SEQUENCE */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* Check ObjectID for the resposeBytes */
    if (GetObjectId(source, &idx, &oid, oidOcspType, size) < 0)
        return ASN_PARSE_E;
    if (oid != OCSP_BASIC_OID)
        return ASN_PARSE_E;
    if (source[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    if (DecodeBasicOcspResponse(source, &idx, resp, size, cm, heap) < 0)
        return ASN_PARSE_E;

    return 0;
}


word32 EncodeOcspRequestExtensions(OcspRequest* req, byte* output, word32 size)
{
    static const byte NonceObjId[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
                                       0x30, 0x01, 0x02 };
    byte seqArray[6][MAX_SEQ_SZ];
    word32 seqSz[6], totalSz = (word32)sizeof(NonceObjId);

    WOLFSSL_ENTER("SetOcspReqExtensions");

    if (!req || !output || !req->nonceSz)
        return 0;

    totalSz += req->nonceSz;
    totalSz += seqSz[0] = SetOctetString(req->nonceSz, seqArray[0]);
    totalSz += seqSz[1] = SetOctetString(req->nonceSz + seqSz[0], seqArray[1]);
    seqArray[2][0] = ASN_OBJECT_ID;
    totalSz += seqSz[2] = 1 + SetLength(sizeof(NonceObjId), &seqArray[2][1]);
    totalSz += seqSz[3] = SetSequence(totalSz, seqArray[3]);
    totalSz += seqSz[4] = SetSequence(totalSz, seqArray[4]);
    totalSz += seqSz[5] = SetExplicit(2, totalSz, seqArray[5]);

    if (totalSz > size)
        return 0;

    totalSz = 0;

    XMEMCPY(output + totalSz, seqArray[5], seqSz[5]);
    totalSz += seqSz[5];

    XMEMCPY(output + totalSz, seqArray[4], seqSz[4]);
    totalSz += seqSz[4];

    XMEMCPY(output + totalSz, seqArray[3], seqSz[3]);
    totalSz += seqSz[3];

    XMEMCPY(output + totalSz, seqArray[2], seqSz[2]);
    totalSz += seqSz[2];

    XMEMCPY(output + totalSz, NonceObjId, sizeof(NonceObjId));
    totalSz += (word32)sizeof(NonceObjId);

    XMEMCPY(output + totalSz, seqArray[1], seqSz[1]);
    totalSz += seqSz[1];

    XMEMCPY(output + totalSz, seqArray[0], seqSz[0]);
    totalSz += seqSz[0];

    XMEMCPY(output + totalSz, req->nonce, req->nonceSz);
    totalSz += req->nonceSz;

    return totalSz;
}


int EncodeOcspRequest(OcspRequest* req, byte* output, word32 size)
{
    byte seqArray[5][MAX_SEQ_SZ];
    /* The ASN.1 of the OCSP Request is an onion of sequences */
    byte algoArray[MAX_ALGO_SZ];
    byte issuerArray[MAX_ENCODED_DIG_SZ];
    byte issuerKeyArray[MAX_ENCODED_DIG_SZ];
    byte snArray[MAX_SN_SZ];
    byte extArray[MAX_OCSP_EXT_SZ];
    word32 seqSz[5], algoSz, issuerSz, issuerKeySz, snSz, extSz, totalSz;
    int i;

    WOLFSSL_ENTER("EncodeOcspRequest");

#ifdef NO_SHA
    algoSz = SetAlgoID(SHA256h, algoArray, oidHashType, 0);
#else
    algoSz = SetAlgoID(SHAh, algoArray, oidHashType, 0);
#endif

    issuerSz    = SetDigest(req->issuerHash,    KEYID_SIZE,    issuerArray);
    issuerKeySz = SetDigest(req->issuerKeyHash, KEYID_SIZE,    issuerKeyArray);
    snSz        = SetSerialNumber(req->serial,  req->serialSz, snArray);
    extSz       = 0;

    if (req->nonceSz)
        extSz = EncodeOcspRequestExtensions(req, extArray, OCSP_NONCE_EXT_SZ);

    totalSz = algoSz + issuerSz + issuerKeySz + snSz;
    for (i = 4; i >= 0; i--) {
        seqSz[i] = SetSequence(totalSz, seqArray[i]);
        totalSz += seqSz[i];
        if (i == 2) totalSz += extSz;
    }

    if (totalSz > size)
        return BUFFER_E;

    totalSz = 0;
    for (i = 0; i < 5; i++) {
        XMEMCPY(output + totalSz, seqArray[i], seqSz[i]);
        totalSz += seqSz[i];
    }

    XMEMCPY(output + totalSz, algoArray, algoSz);
    totalSz += algoSz;

    XMEMCPY(output + totalSz, issuerArray, issuerSz);
    totalSz += issuerSz;

    XMEMCPY(output + totalSz, issuerKeyArray, issuerKeySz);
    totalSz += issuerKeySz;

    XMEMCPY(output + totalSz, snArray, snSz);
    totalSz += snSz;

    if (extSz != 0) {
        XMEMCPY(output + totalSz, extArray, extSz);
        totalSz += extSz;
    }

    return totalSz;
}


int InitOcspRequest(OcspRequest* req, DecodedCert* cert, byte useNonce,
                                                                     void* heap)
{
    WOLFSSL_ENTER("InitOcspRequest");

    if (req == NULL)
        return BAD_FUNC_ARG;

    ForceZero(req, sizeof(OcspRequest));
    req->heap = heap;

    if (cert) {
        XMEMCPY(req->issuerHash,    cert->issuerHash,    KEYID_SIZE);
        XMEMCPY(req->issuerKeyHash, cert->issuerKeyHash, KEYID_SIZE);

        req->serial = (byte*)XMALLOC(cert->serialSz, req->heap,
                                                     DYNAMIC_TYPE_OCSP_REQUEST);
        if (req->serial == NULL)
            return MEMORY_E;

        XMEMCPY(req->serial, cert->serial, cert->serialSz);
        req->serialSz = cert->serialSz;

        if (cert->extAuthInfoSz != 0 && cert->extAuthInfo != NULL) {
            req->url = (byte*)XMALLOC(cert->extAuthInfoSz, req->heap,
                                                     DYNAMIC_TYPE_OCSP_REQUEST);
            if (req->url == NULL) {
                XFREE(req->serial, req->heap, DYNAMIC_TYPE_OCSP);
                return MEMORY_E;
            }

            XMEMCPY(req->url, cert->extAuthInfo, cert->extAuthInfoSz);
            req->urlSz = cert->extAuthInfoSz;
        }

    }

    if (useNonce) {
        WC_RNG rng;

#ifdef WOLFSSL_STATIC_MEMORY
        if (wc_InitRng_ex(&rng, req->heap) != 0) {
#else
        if (wc_InitRng(&rng) != 0) {
#endif
            WOLFSSL_MSG("\tCannot initialize RNG. Skipping the OSCP Nonce.");
        } else {
            if (wc_RNG_GenerateBlock(&rng, req->nonce, MAX_OCSP_NONCE_SZ) != 0)
                WOLFSSL_MSG("\tCannot run RNG. Skipping the OSCP Nonce.");
            else
                req->nonceSz = MAX_OCSP_NONCE_SZ;

            wc_FreeRng(&rng);
        }
    }

    return 0;
}

void FreeOcspRequest(OcspRequest* req)
{
    WOLFSSL_ENTER("FreeOcspRequest");

    if (req) {
        if (req->serial)
            XFREE(req->serial, req->heap, DYNAMIC_TYPE_OCSP_REQUEST);

        if (req->url)
            XFREE(req->url, req->heap, DYNAMIC_TYPE_OCSP_REQUEST);
    }
}


int CompareOcspReqResp(OcspRequest* req, OcspResponse* resp)
{
    int cmp;

    WOLFSSL_ENTER("CompareOcspReqResp");

    if (req == NULL)
    {
        WOLFSSL_MSG("\tReq missing");
        return -1;
    }

    if (resp == NULL)
    {
        WOLFSSL_MSG("\tResp missing");
        return 1;
    }

    /* Nonces are not critical. The responder may not necessarily add
     * the nonce to the response. */
    if (req->nonceSz && resp->nonceSz != 0) {
        cmp = req->nonceSz - resp->nonceSz;
        if (cmp != 0)
        {
            WOLFSSL_MSG("\tnonceSz mismatch");
            return cmp;
        }

        cmp = XMEMCMP(req->nonce, resp->nonce, req->nonceSz);
        if (cmp != 0)
        {
            WOLFSSL_MSG("\tnonce mismatch");
            return cmp;
        }
    }

    cmp = XMEMCMP(req->issuerHash, resp->issuerHash, KEYID_SIZE);
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tissuerHash mismatch");
        return cmp;
    }

    cmp = XMEMCMP(req->issuerKeyHash, resp->issuerKeyHash, KEYID_SIZE);
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tissuerKeyHash mismatch");
        return cmp;
    }

    cmp = req->serialSz - resp->status->serialSz;
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tserialSz mismatch");
        return cmp;
    }

    cmp = XMEMCMP(req->serial, resp->status->serial, req->serialSz);
    if (cmp != 0)
    {
        WOLFSSL_MSG("\tserial mismatch");
        return cmp;
    }

    return 0;
}

#endif


/* store SHA hash of NAME */
WOLFSSL_LOCAL int GetNameHash(const byte* source, word32* idx, byte* hash,
                             int maxIdx)
{
    int    length;  /* length of all distinguished names */
    int    ret;
    word32 dummy;

    WOLFSSL_ENTER("GetNameHash");

    if (source[*idx] == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (GetLength(source, idx, &length, maxIdx) < 0)
            return ASN_PARSE_E;

        *idx += length;
        WOLFSSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    dummy = *idx;
    if (GetSequence(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

#ifdef NO_SHA
    ret = wc_Sha256Hash(source + dummy, length + *idx - dummy, hash);
#else
    ret = wc_ShaHash(source + dummy, length + *idx - dummy, hash);
#endif

    *idx += length;

    return ret;
}


#ifdef HAVE_CRL

/* initialize decoded CRL */
void InitDecodedCRL(DecodedCRL* dcrl, void* heap)
{
    WOLFSSL_MSG("InitDecodedCRL");

    dcrl->certBegin    = 0;
    dcrl->sigIndex     = 0;
    dcrl->sigLength    = 0;
    dcrl->signatureOID = 0;
    dcrl->certs        = NULL;
    dcrl->totalCerts   = 0;
    dcrl->heap         = heap;
    #ifdef WOLFSSL_HEAP_TEST
        dcrl->heap = (void*)WOLFSSL_HEAP_TEST;
    #endif
}


/* free decoded CRL resources */
void FreeDecodedCRL(DecodedCRL* dcrl)
{
    RevokedCert* tmp = dcrl->certs;

    WOLFSSL_MSG("FreeDecodedCRL");

    while(tmp) {
        RevokedCert* next = tmp->next;
        XFREE(tmp, dcrl->heap, DYNAMIC_TYPE_REVOKED);
        tmp = next;
    }
}


/* Get Revoked Cert list, 0 on success */
static int GetRevoked(const byte* buff, word32* idx, DecodedCRL* dcrl,
                      int maxIdx)
{
    int    len;
    word32 end;
    byte   b;
    RevokedCert* rc;

    WOLFSSL_ENTER("GetRevoked");

    if (GetSequence(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    end = *idx + len;

    rc = (RevokedCert*)XMALLOC(sizeof(RevokedCert), dcrl->heap,
                                                          DYNAMIC_TYPE_CRL);
    if (rc == NULL) {
        WOLFSSL_MSG("Alloc Revoked Cert failed");
        return MEMORY_E;
    }

    if (GetSerialNumber(buff, idx, rc->serialNumber, &rc->serialSz,
                                                                maxIdx) < 0) {
        XFREE(rc, dcrl->heap, DYNAMIC_TYPE_CRL);
        return ASN_PARSE_E;
    }

    /* add to list */
    rc->next = dcrl->certs;
    dcrl->certs = rc;
    dcrl->totalCerts++;


    /* get date */
    b = buff[*idx];
    *idx += 1;

    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME) {
        WOLFSSL_MSG("Expecting Date");
        return ASN_PARSE_E;
    }

    if (GetLength(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    /* skip for now */
    *idx += len;

    if (*idx != end)  /* skip extensions */
        *idx = end;

    return 0;
}


/* Get CRL Signature, 0 on success */
static int GetCRL_Signature(const byte* source, word32* idx, DecodedCRL* dcrl,
                            int maxIdx)
{
    int    length;
    byte   b;

    WOLFSSL_ENTER("GetCRL_Signature");

    b = source[*idx];
    *idx += 1;
    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    dcrl->sigLength = length;

    b = source[*idx];
    *idx += 1;
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    dcrl->sigLength--;
    dcrl->signature = (byte*)&source[*idx];

    *idx += dcrl->sigLength;

    return 0;
}


/* prase crl buffer into decoded state, 0 on success */
int ParseCRL(DecodedCRL* dcrl, const byte* buff, word32 sz, void* cm)
{
    int     version, len, doNextDate = 1;
    word32  oid, idx = 0, dateIdx;
    Signer* ca = NULL;

    WOLFSSL_MSG("ParseCRL");

    /* raw crl hash */
    /* hash here if needed for optimized comparisons
     * Sha     sha;
     * wc_InitSha(&sha);
     * wc_ShaUpdate(&sha, buff, sz);
     * wc_ShaFinal(&sha, dcrl->crlHash); */

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;

    dcrl->certBegin = idx;

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;
    dcrl->sigIndex = len + idx;

    /* may have version */
    if (buff[idx] == ASN_INTEGER) {
        if (GetMyVersion(buff, &idx, &version) < 0)
            return ASN_PARSE_E;
    }

    if (GetAlgoId(buff, &idx, &oid, oidIgnoreType, sz) < 0)
        return ASN_PARSE_E;

    if (GetNameHash(buff, &idx, dcrl->issuerHash, sz) < 0)
        return ASN_PARSE_E;

    if (GetBasicDate(buff, &idx, dcrl->lastDate, &dcrl->lastDateFormat, sz) < 0)
        return ASN_PARSE_E;

    dateIdx = idx;

    if (GetBasicDate(buff, &idx, dcrl->nextDate, &dcrl->nextDateFormat, sz) < 0)
    {
#ifndef WOLFSSL_NO_CRL_NEXT_DATE
        (void)dateIdx;
        return ASN_PARSE_E;
#else
        dcrl->nextDateFormat = ASN_OTHER_TYPE;  /* skip flag */
        doNextDate = 0;
        idx = dateIdx;
#endif
    }

    if (doNextDate && !XVALIDATE_DATE(dcrl->nextDate, dcrl->nextDateFormat,
                                      AFTER)) {
        WOLFSSL_MSG("CRL after date is no longer valid");
        return ASN_AFTER_DATE_E;
    }

    if (idx != dcrl->sigIndex && buff[idx] != CRL_EXTENSIONS) {
        if (GetSequence(buff, &idx, &len, sz) < 0)
            return ASN_PARSE_E;

        len += idx;

        while (idx < (word32)len) {
            if (GetRevoked(buff, &idx, dcrl, sz) < 0)
                return ASN_PARSE_E;
        }
    }

    if (idx != dcrl->sigIndex)
        idx = dcrl->sigIndex;   /* skip extensions */

    if (GetAlgoId(buff, &idx, &dcrl->signatureOID, oidSigType, sz) < 0)
        return ASN_PARSE_E;

    if (GetCRL_Signature(buff, &idx, dcrl, sz) < 0)
        return ASN_PARSE_E;

    /* openssl doesn't add skid by default for CRLs cause firefox chokes
       we're not assuming it's available yet */
    #if !defined(NO_SKID) && defined(CRL_SKID_READY)
        if (dcrl->extAuthKeyIdSet)
            ca = GetCA(cm, dcrl->extAuthKeyId);
        if (ca == NULL)
            ca = GetCAByName(cm, dcrl->issuerHash);
    #else /* NO_SKID */
        ca = GetCA(cm, dcrl->issuerHash);
    #endif /* NO_SKID */
    WOLFSSL_MSG("About to verify CRL signature");

    if (ca) {
        WOLFSSL_MSG("Found CRL issuer CA");
        /* try to confirm/verify signature */
        #ifndef IGNORE_KEY_EXTENSIONS
            if ((ca->keyUsage & KEYUSE_CRL_SIGN) == 0) {
                WOLFSSL_MSG("CA cannot sign CRLs");
                return ASN_CRL_NO_SIGNER_E;
            }
        #endif /* IGNORE_KEY_EXTENSIONS */
        if (!ConfirmSignature(buff + dcrl->certBegin,
                dcrl->sigIndex - dcrl->certBegin,
                ca->publicKey, ca->pubKeySize, ca->keyOID,
                dcrl->signature, dcrl->sigLength, dcrl->signatureOID, NULL)) {
            WOLFSSL_MSG("CRL Confirm signature failed");
            return ASN_CRL_CONFIRM_E;
        }
    }
    else {
        WOLFSSL_MSG("Did NOT find CRL issuer CA");
        return ASN_CRL_NO_SIGNER_E;
    }

    return 0;
}

#endif /* HAVE_CRL */
#endif /* !NO_ASN */

#ifdef WOLFSSL_SEP



#endif /* WOLFSSL_SEP */
