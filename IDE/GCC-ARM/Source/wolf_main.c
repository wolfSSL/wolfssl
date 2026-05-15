/* wolf_main.c
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


#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h> /* for CUSTOM_RAND_TYPE */

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifdef NO_ASN_TIME
    #include <time.h>
#endif


/* TIME CODE */
/* TODO: Implement real RTC */
/* Optionally you can define NO_ASN_TIME to disable all cert time checks */
static int gTimeMs;
static int hw_get_time_sec(void)
{
    #warning Must implement your own time source if validating certificates

    return ++gTimeMs;
}

static int IsLeapYear(int year)
{
    return ((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0));
}

/* This is used by wolfCrypt asn.c for cert time checking */
time_t my_time(time_t* timer)
{
    time_t curTime = (time_t)hw_get_time_sec();

    if (timer != NULL) {
        *timer = curTime;
    }

    return curTime;
}

struct tm* my_gmtime(const time_t* timer, struct tm* tmp)
{
    static struct tm staticTime;
    static const unsigned char daysPerMonth[] =
        { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    time_t curTime;
    long days;
    long rem;
    int year;
    int yearDays;
    int month;
    int monthDays;

    if (tmp == NULL) {
        tmp = &staticTime;
    }

    curTime = (timer != NULL) ? *timer : my_time(NULL);
    if (curTime < 0) {
        curTime = 0;
    }

    days = (long)(curTime / 86400);
    rem = (long)(curTime % 86400);

    tmp->tm_hour = (int)(rem / 3600);
    rem %= 3600;
    tmp->tm_min = (int)(rem / 60);
    tmp->tm_sec = (int)(rem % 60);
    tmp->tm_wday = (int)((days + 4) % 7);

    year = 1970;
    while (1) {
        yearDays = IsLeapYear(year) ? 366 : 365;
        if (days < yearDays) {
            break;
        }
        days -= yearDays;
        year++;
    }

    tmp->tm_year = year - 1900;
    tmp->tm_yday = (int)days;

    for (month = 0; month < 12; month++) {
        monthDays = daysPerMonth[month];
        if (month == 1 && IsLeapYear(year)) {
            monthDays++;
        }
        if (days < monthDays) {
            break;
        }
        days -= monthDays;
    }

    tmp->tm_mon = month;
    tmp->tm_mday = (int)days + 1;
    tmp->tm_isdst = 0;

    return tmp;
}

#ifndef WOLFCRYPT_ONLY
/* This is used by TLS only */
word32 LowResTimer(void)
{
    return (word32)hw_get_time_sec();
}

/* This is used by TLS 1.3 ticket and PSK timeouts. */
#ifdef WOLFSSL_32BIT_MILLI_TIME
word32 TimeNowInMilliseconds(void)
#else
sword64 TimeNowInMilliseconds(void)
#endif
{
    return (sword64)my_time(NULL) * 1000;
}
#endif

#ifndef NO_CRYPT_BENCHMARK
/* This is used by wolfCrypt benchmark tool only */
double current_time(int reset)
{
    double timeNow;
    int timeMs = gTimeMs;
    (void)reset;
    timeNow = (timeMs / 1000); // sec
    timeNow += (double)(timeMs % 1000) / 1000; // ms
    return timeNow;
}
#endif

/* RNG CODE */
/* TODO: Implement real RNG */
static unsigned int gCounter;
unsigned int hw_rand(void)
{
    #warning Must implement your own random source

    return ++gCounter;
}

unsigned int my_rng_seed_gen(void)
{
    return hw_rand();
}

int my_rng_gen_block(unsigned char* output, unsigned int sz)
{
    uint32_t i = 0;

    while (i < sz)
    {
        /* If not aligned or there is odd/remainder */
        if( (i + sizeof(CUSTOM_RAND_TYPE)) > sz ||
            ((uint32_t)&output[i] % sizeof(CUSTOM_RAND_TYPE)) != 0
        ) {
            /* Single byte at a time */
            output[i++] = (unsigned char)my_rng_seed_gen();
        }
        else {
            /* Use native 8, 16, 32 or 64 copy instruction */
            *((CUSTOM_RAND_TYPE*)&output[i]) = my_rng_seed_gen();
            i += sizeof(CUSTOM_RAND_TYPE);
        }
    }

    return 0;
}


#ifdef XMALLOC_OVERRIDE
void *myMalloc(size_t n, void* heap, int type)
{
    (void)n;
    (void)heap;
    (void)type;

    #warning Must implement your own malloc

    return NULL;
}
void myFree(void *p, void* heap, int type)
{
    (void)p;
    (void)heap;
    (void)type;

    #warning Must implement your own free
}

/* Required for normal math (!USE_FAST_MATH) */
void *myRealloc(void *p, size_t n, void* heap, int type)
{
    (void)p;
    (void)n;
    (void)heap;
    (void)type;

    #warning Must implement your own realloc

    return NULL;
}
#endif /* XMALLOC_OVERRIDE */
