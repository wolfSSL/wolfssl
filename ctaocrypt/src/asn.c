/* asn.c
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifdef THREADX
    #include "os.h"           /* dc_rtc_api needs    */
    #include "dc_rtc_api.h"   /* to get current time */
#endif
#include "asn.h"
#include "coding.h"
#include "ctc_sha.h"
#include "ctc_md5.h"
#include "error.h"

#ifdef HAVE_NTRU
    #include "crypto_ntru.h"
#endif

#ifdef HAVE_ECC
    #include "ctc_ecc.h"
#endif


#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of XSTRNCPY */
    #pragma warning(disable: 4996)
#endif


#ifndef TRUE
enum {
    FALSE = 0,
    TRUE  = 1
};
#endif


#ifdef THREADX
    /* uses parital <time.h> structures */
    #define XTIME(tl)  (0)
    #define XGMTIME(c) my_gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#elif defined(MICRIUM)
    #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
        #define XVALIDATE_DATE(d,f,t) NetSecure_ValidateDateHandler((d),(f),(t))
    #else
        #define XVALIDATE_DATE(d, f, t) (0)
    #endif
    #define NO_TIME_H
    /* since Micrium not defining XTIME or XGMTIME, CERT_GEN not available */
#elif defined(USER_TIME)
    /* no <time.h> strucutres used */
    #define NO_TIME_H
    /* user time, and gmtime compatible functions, there is a gmtime 
       implementation here that WINCE uses, so really just need some ticks
       since the EPOCH 
    */
#else
    /* default */
    /* uses complete <time.h> facility */
    #include <time.h> 
    #define XTIME(tl)  time((tl))
    #define XGMTIME(c) gmtime((c))
    #define XVALIDATE_DATE(d, f, t) ValidateDate((d), (f), (t))
#endif


#ifdef _WIN32_WCE
/* no time() or gmtime() even though in time.h header?? */

#include <windows.h>


time_t time(time_t* timer)
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
    time_t time = *timer;
    unsigned long dayclock, dayno;
    int year = EPOCH_YEAR;

    dayclock = (unsigned long)time % SECS_DAY;
    dayno    = (unsigned long)time / SECS_DAY;

    ret->tm_sec  =  dayclock % 60;
    ret->tm_min  = (dayclock % 3600) / 60;
    ret->tm_hour =  dayclock / 3600;
    ret->tm_wday = (dayno + 4) % 7;        /* day 0 a Thursday */

    while(dayno >= (unsigned long)YEARSIZE(year)) {
        dayno -= YEARSIZE(year);
        year++;
    }

    ret->tm_year = year - YEAR0;
    ret->tm_yday = dayno;
    ret->tm_mon  = 0;

    while(dayno >= (unsigned long)_ytab[LEAPYEAR(year)][ret->tm_mon]) {
        dayno -= _ytab[LEAPYEAR(year)][ret->tm_mon];
        ret->tm_mon++;
    }

    ret->tm_mday  = ++dayno;
    ret->tm_isdst = 0;

    return ret;
}

#endif /* _WIN32_WCE */



#ifdef  THREADX

#define YEAR0          1900

struct tm* my_gmtime(const time_t* timer)       /* has a gmtime() but hangs */
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

#endif /* THREADX */


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


int GetLength(const byte* input, word32* inOutIdx, int* len)
{
    int     length = 0;
    word32  i = *inOutIdx;

    byte b = input[i++];
    if (b >= ASN_LONG_LENGTH) {        
        word32 bytes = b & 0x7F;

        while (bytes--) {
            b = input[i++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;
    
    *inOutIdx = i;
    *len      = length;

    return length;
}


int GetSequence(const byte* input, word32* inOutIdx, int* len)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


int GetSet(const byte* input, word32* inOutIdx, int* len)
{
    int    length = -1;
    word32 idx    = *inOutIdx;

    if (input[idx++] != (ASN_SET | ASN_CONSTRUCTED) ||
            GetLength(input, &idx, &length) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;

    return length;
}


/* winodws header clash for WinCE using GetVersion */
int GetMyVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    if (input[idx++] != 0x01)
        return ASN_VERSION_E;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
}


/* May not have one, not an error */
int GetExplicitVersion(const byte* input, word32* inOutIdx, int* version)
{
    word32 idx = *inOutIdx;

    if (input[idx++] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        *inOutIdx = ++idx;  /* eat header */
        return GetMyVersion(input, inOutIdx, version);
    }

    /* go back as is */
    *version = 0;

    return 0;
}


int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx )
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    mp_init(mpi); 
    if (mp_read_unsigned_bin(mpi, (byte*)input + i, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

    *inOutIdx = i + length;
    return 0;
}


static int GetAlgoId(const byte* input, word32* inOutIdx, word32* oid)
{
    int    length;
    word32 i = *inOutIdx;
    byte   b;
    *oid = 0;
    
    if (GetSequence(input, &i, &length) < 0)
        return ASN_PARSE_E;
    
    b = input[i++];
    if (b != ASN_OBJECT_ID) 
        return ASN_OBJECT_ID_E;
    
    if (GetLength(input, &i, &length) < 0)
        return ASN_PARSE_E;
    
    while(length--)
        *oid += input[i++];
    /* just sum it up for now */
    
    /* could have NULL tag and 0 terminator, but may not */
    b = input[i++];
    
    if (b == ASN_TAG_NULL) {
        b = input[i++];
        if (b != 0) 
            return ASN_EXPECT_0_E;
    }
    else
    /* go back, didn't have it */
        i--;
    
    *inOutIdx = i;
    
    return 0;
}


int RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                        word32 inSz)
{
    word32 begin = *inOutIdx;
    int    version, length;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetInt(&key->n,  input, inOutIdx) < 0 ||
        GetInt(&key->e,  input, inOutIdx) < 0 ||
        GetInt(&key->d,  input, inOutIdx) < 0 ||
        GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->q,  input, inOutIdx) < 0 ||
        GetInt(&key->dP, input, inOutIdx) < 0 ||
        GetInt(&key->dQ, input, inOutIdx) < 0 ||
        GetInt(&key->u,  input, inOutIdx) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}


/* Remove PKCS8 header, move beginning of traditional to beginning of input */
int ToTraditional(byte* input, word32 sz)
{
    word32 inOutIdx = 0, oid;
    int    version, length;

    if (GetSequence(input, &inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (sz - inOutIdx))
        return ASN_INPUT_E;

    if (GetMyVersion(input, &inOutIdx, &version) < 0)
        return ASN_PARSE_E;
    
    if (GetAlgoId(input, &inOutIdx, &oid) < 0)
        return ASN_PARSE_E;
    
    if (input[inOutIdx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;
    
    if (GetLength(input, &inOutIdx, &length) < 0)
        return ASN_PARSE_E;
    
    if ((word32)length > (sz - inOutIdx))
        return ASN_INPUT_E;
    
    XMEMMOVE(input, input + inOutIdx, length);

    return 0;
}


int RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                       word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length;
    byte   b;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    key->type = RSA_PUBLIC;
    b = input[*inOutIdx];

#ifdef OPENSSL_EXTRA    
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length) < 0)
            return ASN_PARSE_E;
        
        b = input[(*inOutIdx)++];
        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;
        
        if (GetLength(input, inOutIdx, &length) < 0)
            return ASN_PARSE_E;
        
        *inOutIdx += length;   /* skip past */
        
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
        
        if (GetLength(input, inOutIdx, &length) < 0)
            return ASN_PARSE_E;
        
        /* could have 0 */
        b = input[(*inOutIdx)++];
        if (b != 0)
            (*inOutIdx)--;
        
        if (GetSequence(input, inOutIdx, &length) < 0)
            return ASN_PARSE_E;
    }
#endif /* OPENSSL_EXTRA */

    if (GetInt(&key->n,  input, inOutIdx) < 0 ||
        GetInt(&key->e,  input, inOutIdx) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}


#ifndef NO_DH

int DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->g,  input, inOutIdx) < 0 )  return ASN_DH_KEY_E;

    return 0;
}

int DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g, word32 gSz)
{
    /* may have leading 0 */
    if (p[0] == 0) {
        pSz--; p++;
    }

    if (g[0] == 0) {
        gSz--; g++;
    }

    mp_init(&key->p);
    if (mp_read_unsigned_bin(&key->p, p, pSz) != 0) {
        mp_clear(&key->p);
        return ASN_DH_KEY_E;
    }

    mp_init(&key->g);
    if (mp_read_unsigned_bin(&key->g, g, gSz) != 0) {
        mp_clear(&key->p);
        return ASN_DH_KEY_E;
    }

    return 0;
}


#endif /* NO_DH */


#ifndef NO_DSA

int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->q,  input, inOutIdx) < 0 ||
        GetInt(&key->g,  input, inOutIdx) < 0 ||
        GetInt(&key->y,  input, inOutIdx) < 0 )  return ASN_DH_KEY_E;

    key->type = DSA_PUBLIC;
    return 0;
}


int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                        word32 inSz)
{
    word32 begin = *inOutIdx;
    int    length, version;

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetInt(&key->p,  input, inOutIdx) < 0 ||
        GetInt(&key->q,  input, inOutIdx) < 0 ||
        GetInt(&key->g,  input, inOutIdx) < 0 ||
        GetInt(&key->y,  input, inOutIdx) < 0 ||
        GetInt(&key->x,  input, inOutIdx) < 0 )  return ASN_DH_KEY_E;

    key->type = DSA_PRIVATE;
    return 0;
}

#endif /* NO_DSA */


void InitDecodedCert(DecodedCert* cert, byte* source, void* heap)
{
    cert->publicKey       = 0;
    cert->pubKeyStored    = 0;
    cert->signature       = 0;
    cert->subjectCN       = 0;
    cert->subjectCNLen    = 0;
    cert->source          = source;  /* don't own */
    cert->srcIdx          = 0;
    cert->heap            = heap;
#ifdef CYASSL_CERT_GEN
    cert->subjectSN       = 0;
    cert->subjectSNLen    = 0;
    cert->subjectC        = 0;
    cert->subjectCLen     = 0;
    cert->subjectL        = 0;
    cert->subjectLLen     = 0;
    cert->subjectST       = 0;
    cert->subjectSTLen    = 0;
    cert->subjectO        = 0;
    cert->subjectOLen     = 0;
    cert->subjectOU       = 0;
    cert->subjectOULen    = 0;
    cert->subjectEmail    = 0;
    cert->subjectEmailLen = 0;
#endif /* CYASSL_CERT_GEN */
}


void FreeDecodedCert(DecodedCert* cert)
{
    if (cert->subjectCNLen == 0)  /* 0 means no longer pointer to raw, we own */
        XFREE(cert->subjectCN, cert->heap, DYNAMIC_TYPE_SUBJECT_CN);
    if (cert->pubKeyStored == 1)
        XFREE(cert->publicKey, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
}


static int GetCertHeader(DecodedCert* cert, word32 inSz)
{
    int    ret = 0, version, len;
    word32 begin = cert->srcIdx;
    mp_int mpi;

    if (GetSequence(cert->source, &cert->srcIdx, &len) < 0)
        return ASN_PARSE_E;

    if ((word32)len > (inSz - (cert->srcIdx - begin))) return ASN_INPUT_E;

    cert->certBegin = cert->srcIdx;

    GetSequence(cert->source, &cert->srcIdx, &len);
    cert->sigIndex = len + cert->srcIdx;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &version) < 0)
        return ASN_PARSE_E;

    if (GetInt(&mpi, cert->source, &cert->srcIdx) < 0) 
        ret = ASN_PARSE_E;

    mp_clear(&mpi);
    return ret;
}


/* Store Rsa Key, may save later, Dsa could use in future */
static int StoreRsaKey(DecodedCert* cert)
{
    int    length;
    word32 read = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;
   
    read = cert->srcIdx - read;
    length += read;

    while (read--)
       cert->srcIdx--;

    cert->pubKeySize = length;
    cert->publicKey = cert->source + cert->srcIdx;
    cert->srcIdx += length;

    return 0;
}


#ifdef HAVE_ECC

    /* return 0 on sucess if the ECC curve oid sum is supported */
    static int CheckCurve(word32 oid)
    {
        if (oid != ECC_256R1 && oid != ECC_384R1 && oid != ECC_521R1 && oid !=
                   ECC_160R1 && oid != ECC_192R1 && oid != ECC_224R1)
            return -1;

        return 0;
    }

#endif /* HAVE_ECC */


static int GetKey(DecodedCert* cert)
{
    int length;
#ifdef HAVE_NTRU
    int tmpIdx = cert->srcIdx;
#endif

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;
    
    if (GetAlgoId(cert->source, &cert->srcIdx, &cert->keyOID) < 0)
        return ASN_PARSE_E;

    if (cert->keyOID == RSAk) {
        byte b = cert->source[cert->srcIdx++];
        if (b != ASN_BIT_STRING)
            return ASN_BITSTR_E;

        if (GetLength(cert->source, &cert->srcIdx, &length) < 0)
            return ASN_PARSE_E;
        b = cert->source[cert->srcIdx++];
        if (b != 0x00)
            return ASN_EXPECT_0_E;
    }
    else if (cert->keyOID == DSAk )
        ;   /* do nothing */
#ifdef HAVE_NTRU
    else if (cert->keyOID == NTRUk ) {
        const byte* key = &cert->source[tmpIdx];
        byte*       next = (byte*)key;
        word16      keyLen;
        byte        keyBlob[MAX_NTRU_KEY_SZ];

        word32 rc = crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key,
                            &keyLen, NULL, &next);

        if (rc != NTRU_OK)
            return ASN_NTRU_KEY_E;
        if (keyLen > sizeof(keyBlob))
            return ASN_NTRU_KEY_E;

        rc = crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(key, &keyLen,
                                                                keyBlob, &next);
        if (rc != NTRU_OK)
            return ASN_NTRU_KEY_E;

        if ( (next - key) < 0)
            return ASN_NTRU_KEY_E;

        cert->srcIdx = tmpIdx + (next - key);

        cert->publicKey = (byte*) XMALLOC(keyLen, cert->heap,
                                          DYNAMIC_TYPE_PUBLIC_KEY);
        if (cert->publicKey == NULL)
            return MEMORY_E;
        memcpy(cert->publicKey, keyBlob, keyLen);
        cert->pubKeyStored = 1;
        cert->pubKeySize   = keyLen;
    }
#endif /* HAVE_NTRU */
#ifdef HAVE_ECC
    else if (cert->keyOID == ECDSAk ) {
        word32 oid = 0;
        int    oidSz = 0;
        byte   b = cert->source[cert->srcIdx++];
    
        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;

        if (GetLength(cert->source, &cert->srcIdx, &oidSz) < 0)
            return ASN_PARSE_E;

        while(oidSz--)
            oid += cert->source[cert->srcIdx++];
        if (CheckCurve(oid) < 0)
            return ECC_CURVE_OID_E;

        /* key header */
        b = cert->source[cert->srcIdx++];
        if (b != ASN_BIT_STRING)
            return ASN_BITSTR_E;

        if (GetLength(cert->source, &cert->srcIdx, &length) < 0)
            return ASN_PARSE_E;
        b = cert->source[cert->srcIdx++];
        if (b != 0x00)
            return ASN_EXPECT_0_E;

        /* actual key, use length - 1 since preceding 0 */
        cert->publicKey = (byte*) XMALLOC(length - 1, cert->heap,
                                          DYNAMIC_TYPE_PUBLIC_KEY);
        if (cert->publicKey == NULL)
            return MEMORY_E;
        memcpy(cert->publicKey, &cert->source[cert->srcIdx], length - 1);
        cert->pubKeyStored = 1;
        cert->pubKeySize   = length - 1;

        cert->srcIdx += length;
    }
#endif /* HAVE_ECC */
    else
        return ASN_UNKNOWN_OID_E;
   
    if (cert->keyOID == RSAk) 
        return StoreRsaKey(cert);
    return 0;
}


/* process NAME, either issuer or subject */
static int GetName(DecodedCert* cert, int nameType)
{
    Sha    sha;
    int    length;  /* length of all distinguished names */
    int    dummy;
    char* full = (nameType == ISSUER) ? cert->issuer : cert->subject;
    word32 idx = 0;

    InitSha(&sha);

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;

    length += cert->srcIdx;

    while (cert->srcIdx < (word32)length) {
        byte   b;
        byte   joint[2];
        int    oidSz;

        if (GetSet(cert->source, &cert->srcIdx, &dummy) < 0)
            return ASN_PARSE_E;

        if (GetSequence(cert->source, &cert->srcIdx, &dummy) < 0)
            return ASN_PARSE_E;

        b = cert->source[cert->srcIdx++];
        if (b != ASN_OBJECT_ID) 
            return ASN_OBJECT_ID_E;

        if (GetLength(cert->source, &cert->srcIdx, &oidSz) < 0)
            return ASN_PARSE_E;

        XMEMCPY(joint, &cert->source[cert->srcIdx], sizeof(joint));

        /* v1 name types */
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            byte   id;
            byte   copy = FALSE;
            int    strLen;

            cert->srcIdx += 2;
            id = cert->source[cert->srcIdx++]; 
            b  = cert->source[cert->srcIdx++];    /* strType */

            if (GetLength(cert->source, &cert->srcIdx, &strLen) < 0)
                return ASN_PARSE_E;

            if (strLen > (int)(ASN_NAME_MAX - idx))
                return ASN_PARSE_E; 

            if (4  > (ASN_NAME_MAX - idx))  /* make sure room for biggest */
                return ASN_PARSE_E;         /* pre fix header too "/CN=" */

            if (id == ASN_COMMON_NAME) {
                if (nameType == SUBJECT) {
                    cert->subjectCN = (char *)&cert->source[cert->srcIdx];
                    cert->subjectCNLen = strLen;
                }

                XMEMCPY(&full[idx], "/CN=", 4);
                idx += 4;
                copy = TRUE;
            }
            else if (id == ASN_SUR_NAME) {
                XMEMCPY(&full[idx], "/SN=", 4);
                idx += 4;
                copy = TRUE;
#ifdef CYASSL_CERT_GEN
                if (nameType == SUBJECT) {
                    cert->subjectSN = (char*)&cert->source[cert->srcIdx];
                    cert->subjectSNLen = strLen;
                }
#endif /* CYASSL_CERT_GEN */
            }
            else if (id == ASN_COUNTRY_NAME) {
                XMEMCPY(&full[idx], "/C=", 3);
                idx += 3;
                copy = TRUE;
#ifdef CYASSL_CERT_GEN
                if (nameType == SUBJECT) {
                    cert->subjectC = (char*)&cert->source[cert->srcIdx];
                    cert->subjectCLen = strLen;
                }
#endif /* CYASSL_CERT_GEN */
            }
            else if (id == ASN_LOCALITY_NAME) {
                XMEMCPY(&full[idx], "/L=", 3);
                idx += 3;
                copy = TRUE;
#ifdef CYASSL_CERT_GEN
                if (nameType == SUBJECT) {
                    cert->subjectL = (char*)&cert->source[cert->srcIdx];
                    cert->subjectLLen = strLen;
                }
#endif /* CYASSL_CERT_GEN */
            }
            else if (id == ASN_STATE_NAME) {
                XMEMCPY(&full[idx], "/ST=", 4);
                idx += 4;
                copy = TRUE;
#ifdef CYASSL_CERT_GEN
                if (nameType == SUBJECT) {
                    cert->subjectST = (char*)&cert->source[cert->srcIdx];
                    cert->subjectSTLen = strLen;
                }
#endif /* CYASSL_CERT_GEN */
            }
            else if (id == ASN_ORG_NAME) {
                XMEMCPY(&full[idx], "/O=", 3);
                idx += 3;
                copy = TRUE;
#ifdef CYASSL_CERT_GEN
                if (nameType == SUBJECT) {
                    cert->subjectO = (char*)&cert->source[cert->srcIdx];
                    cert->subjectOLen = strLen;
                }
#endif /* CYASSL_CERT_GEN */
            }
            else if (id == ASN_ORGUNIT_NAME) {
                XMEMCPY(&full[idx], "/OU=", 4);
                idx += 4;
                copy = TRUE;
#ifdef CYASSL_CERT_GEN
                if (nameType == SUBJECT) {
                    cert->subjectOU = (char*)&cert->source[cert->srcIdx];
                    cert->subjectOULen = strLen;
                }
#endif /* CYASSL_CERT_GEN */
            }

            if (copy) {
                XMEMCPY(&full[idx], &cert->source[cert->srcIdx], strLen);
                idx += strLen;
            }

            ShaUpdate(&sha, &cert->source[cert->srcIdx], strLen);
            cert->srcIdx += strLen;
        }
        else {
            /* skip */
            byte email = FALSE;
            int  adv;

            if (joint[0] == 0x2a && joint[1] == 0x86)  /* email id hdr */
                email = TRUE;

            cert->srcIdx += oidSz + 1;

            if (GetLength(cert->source, &cert->srcIdx, &adv) < 0)
                return ASN_PARSE_E;

            if (adv > (int)(ASN_NAME_MAX - idx))
                return ASN_PARSE_E; 

            if (email) {
                if (14 > (ASN_NAME_MAX - idx))
                    return ASN_PARSE_E; 
                XMEMCPY(&full[idx], "/emailAddress=", 14);
                idx += 14;

#ifdef CYASSL_CERT_GEN
                if (nameType == SUBJECT) {
                    cert->subjectEmail = (char*)&cert->source[cert->srcIdx];
                    cert->subjectEmailLen = adv;
                }
#endif /* CYASSL_CERT_GEN */

                XMEMCPY(&full[idx], &cert->source[cert->srcIdx], adv);
                idx += adv;
            }

            cert->srcIdx += adv;
        }
    }
    full[idx++] = 0;

    if (nameType == ISSUER)
        ShaFinal(&sha, cert->issuerHash);
    else
        ShaFinal(&sha, cert->subjectHash);

    return 0;
}


#ifndef NO_TIME_H

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
    return !DateGreaterThan(a,b);
}


/* like atoi but only use first byte */
/* Make sure before and after dates are valid */
static int ValidateDate(const byte* date, byte format, int dateType)
{
    time_t ltime;
    struct tm  certTime;
    struct tm* localTime;
    int    i = 0;

    ltime = XTIME(0);
    XMEMSET(&certTime, 0, sizeof(certTime));

    if (format == ASN_UTC_TIME) {
        if (btoi(date[0]) >= 5)
            certTime.tm_year = 1900;
        else
            certTime.tm_year = 2000;
    }
    else  { /* format == GENERALIZED_TIME */
        certTime.tm_year += btoi(date[i++]) * 1000;
        certTime.tm_year += btoi(date[i++]) * 100;
    }

    GetTime(&certTime.tm_year, date, &i); certTime.tm_year -= 1900; /* adjust */
    GetTime(&certTime.tm_mon,  date, &i); certTime.tm_mon  -= 1;    /* adjust */
    GetTime(&certTime.tm_mday, date, &i);
    GetTime(&certTime.tm_hour, date, &i); 
    GetTime(&certTime.tm_min,  date, &i); 
    GetTime(&certTime.tm_sec,  date, &i); 

    if (date[i] != 'Z')     /* only Zulu supported for this profile */
        return 0;

    localTime = XGMTIME(&ltime);

    if (dateType == BEFORE) {
        if (DateLessThan(localTime, &certTime))
            return 0;
    }
    else
        if (DateGreaterThan(localTime, &certTime))
            return 0;

    return 1;
}

#endif /* NO_TIME_H */


static int GetDate(DecodedCert* cert, int dateType)
{
    int    length;
    byte   date[MAX_DATE_SIZE];
    byte   b = cert->source[cert->srcIdx++];

    if (b != ASN_UTC_TIME && b != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    if (GetLength(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;

    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    XMEMCPY(date, &cert->source[cert->srcIdx], length);
    cert->srcIdx += length;

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

    if (GetSequence(cert->source, &cert->srcIdx, &length) < 0)
        return ASN_PARSE_E;

    if (GetDate(cert, BEFORE) < 0 && verify)
        badDate = ASN_BEFORE_DATE_E;           /* continue parsing */
    
    if (GetDate(cert, AFTER) < 0 && verify)
        return ASN_AFTER_DATE_E;
   
    if (badDate != 0)
        return badDate;

    return 0;
}


static int DecodeToKey(DecodedCert* cert, word32 inSz, int verify)
{
    int badDate = 0;
    int ret;

    if ( (ret = GetCertHeader(cert, inSz)) < 0)
        return ret;

    if ( (ret = GetAlgoId(cert->source, &cert->srcIdx,&cert->signatureOID)) < 0)
        return ret;

    if ( (ret = GetName(cert, ISSUER)) < 0)
        return ret;

    if ( (ret = GetValidity(cert, verify)) < 0)
        badDate = ret;

    if ( (ret = GetName(cert, SUBJECT)) < 0)
        return ret;

    if ( (ret = GetKey(cert)) < 0)
        return ret;

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

    if (GetLength(cert->source, &cert->srcIdx, &length) < 0)
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


static word32 SetDigest(const byte* digest, word32 digSz, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = digSz;
    XMEMCPY(&output[2], digest, digSz);

    return digSz + 2;
} 


static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> (i - 1) * 8)
            break;

    return i;
}


static word32 SetLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = length;
    else {
        output[i++] = BytePrecision(length) | ASN_LONG_LENGTH;
      
        for (j = BytePrecision(length); j; --j) {
            output[i] = length >> (j - 1) * 8;
            i++;
        }
    }

    return i;
}


static word32 SetSequence(word32 len, byte* output)
{
    output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}


static word32 SetAlgoID(int algoOID, byte* output, int type)
{
    /* adding TAG_NULL and 0 to end */
    
    /* hashTypes */
    static const byte shaAlgoID[] = { 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                                      0x05, 0x00 };
    static const byte md5AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x02, 0x05, 0x05, 0x00  };
    static const byte md2AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x02, 0x02, 0x05, 0x00};

    /* sigTypes */
    static const byte md5wRSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x01, 0x01, 0x04, 0x05, 0x00};

    /* keyTypes */
    static const byte RSA_AlgoID[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                      0x01, 0x01, 0x01, 0x05, 0x00};

    int    algoSz = 0;
    word32 idSz, seqSz;
    const  byte* algoName = 0;
    byte ID_Length[MAX_LENGTH_SZ];
    byte seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */

    if (type == hashType) {
        switch (algoOID) {
        case SHAh:
            algoSz = sizeof(shaAlgoID);
            algoName = shaAlgoID;
            break;

        case MD2h:
            algoSz = sizeof(md2AlgoID);
            algoName = md2AlgoID;
            break;

        case MD5h:
            algoSz = sizeof(md5AlgoID);
            algoName = md5AlgoID;
            break;

        default:
            return 0;  /* UNKOWN_HASH_E; */
        }
    }
    else if (type == sigType) {    /* sigType */
        switch (algoOID) {
        case MD5wRSA:
            algoSz = sizeof(md5wRSA_AlgoID);
            algoName = md5wRSA_AlgoID;
            break;

        default:
            return 0;  /* UNKOWN_HASH_E; */
        }
    }
    else if (type == keyType) {    /* keyType */
        switch (algoOID) {
        case RSAk:
            algoSz = sizeof(RSA_AlgoID);
            algoName = RSA_AlgoID;
            break;

        default:
            return 0;  /* UNKOWN_HASH_E; */
        }
    }
    else
        return 0;  /* UNKNOWN_TYPE */


    idSz  = SetLength(algoSz - 2, ID_Length); /* don't include TAG_NULL/0 */
    seqSz = SetSequence(idSz + algoSz + 1, seqArray);
    seqArray[seqSz++] = ASN_OBJECT_ID;

    XMEMCPY(output, seqArray, seqSz);
    XMEMCPY(output + seqSz, ID_Length, idSz);
    XMEMCPY(output + seqSz + idSz, algoName, algoSz);

    return seqSz + idSz + algoSz;

}


word32 EncodeSignature(byte* out, const byte* digest, word32 digSz, int hashOID)
{
    byte digArray[MAX_ENCODED_DIG_SZ];
    byte algoArray[MAX_ALGO_SZ];
    byte seqArray[MAX_SEQ_SZ];
    word32 encDigSz, algoSz, seqSz; 

    encDigSz = SetDigest(digest, digSz, digArray);
    algoSz   = SetAlgoID(hashOID, algoArray, hashType);
    seqSz    = SetSequence(encDigSz + algoSz, seqArray);

    XMEMCPY(out, seqArray, seqSz);
    XMEMCPY(out + seqSz, algoArray, algoSz);
    XMEMCPY(out + seqSz + algoSz, digArray, encDigSz);

    return encDigSz + algoSz + seqSz;
}
                           

/* return true (1) for Confirmation */
static int ConfirmSignature(DecodedCert* cert, const byte* key, word32 keySz,
                            word32 keyOID)
{
    byte digest[SHA_DIGEST_SIZE]; /* max size */
    int  hashType, digestSz, ret;

    if (cert->signatureOID == MD5wRSA) {
        Md5 md5;
        InitMd5(&md5);
        Md5Update(&md5, cert->source + cert->certBegin,
                  cert->sigIndex - cert->certBegin);
        Md5Final(&md5, digest);
        hashType = MD5h;
        digestSz = MD5_DIGEST_SIZE;
    }
    else if (cert->signatureOID == SHAwRSA || cert->signatureOID == SHAwDSA ||
                                              cert->signatureOID == SHAwECDSA) {
        Sha sha;
        InitSha(&sha);
        ShaUpdate(&sha, cert->source + cert->certBegin,
                  cert->sigIndex - cert->certBegin);
        ShaFinal(&sha, digest);
        hashType = SHAh;
        digestSz = SHA_DIGEST_SIZE;
    }
    else
        return 0; /* ASN_SIG_HASH_E; */

    if (keyOID == RSAk) {
        RsaKey pubKey;
        byte   encodedSig[MAX_ENCODED_SIG_SZ];
        byte   plain[MAX_ENCODED_SIG_SZ];
        word32 idx = 0;
        int    sigSz, verifySz;
        byte*  out;

        if (cert->sigLength > MAX_ENCODED_SIG_SZ)
            return 0; /* the key is too big */
            
        InitRsaKey(&pubKey, cert->heap);
        if (RsaPublicKeyDecode(key, &idx, &pubKey, keySz) < 0)
            ret = 0; /* ASN_KEY_DECODE_E; */

        else {
            XMEMCPY(plain, cert->signature, cert->sigLength);
            if ( (verifySz = RsaSSL_VerifyInline(plain, cert->sigLength, &out,
                                           &pubKey)) < 0)
                ret = 0; /* ASN_VERIFY_E; */
            else {
                /* make sure we're right justified */
                sigSz = EncodeSignature(encodedSig, digest, digestSz, hashType);
                if (sigSz != verifySz || XMEMCMP(out, encodedSig, sigSz) != 0)
                    ret = 0; /* ASN_VERIFY_MATCH_E; */
                else
                    ret = 1; /* match */
            }
        }
        FreeRsaKey(&pubKey);
        return ret;
    }
#ifdef HAVE_ECC
    else if (keyOID == ECDSAk) {
        ecc_key pubKey;
        int     verify = 0;
        
        if (ecc_import_x963(key, keySz, &pubKey) < 0)
            return 0; /* ASN_KEY_DECODE_E */
    
        ret = ecc_verify_hash(cert->signature, cert->sigLength, digest,
                              digestSz, &verify, &pubKey);
        ecc_free(&pubKey);
        if (ret == 0 && verify == 1)
            return 1;  /* match */

        return 0;  /* ASN_VERIFY_E */
    }
#endif /* HAVE_ECC */
    else
        return 0; /* ASN_SIG_KEY_E; */
}


int ParseCert(DecodedCert* cert, word32 inSz, int type, int verify,
              Signer* signers)
{
    int   ret;
    char* ptr;

    ret = ParseCertRelative(cert, inSz, type, verify, signers);
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
        cert->subjectCNLen = 0;
    }

    if (cert->keyOID == RSAk && cert->pubKeySize > 0) {
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


int ParseCertRelative(DecodedCert* cert, word32 inSz, int type, int verify,
              Signer* signers)
{
    word32 confirmOID;
    int    ret;
    int    badDate = 0;
    int    confirm = 0;

    if ((ret = DecodeToKey(cert, inSz, verify)) < 0) {
        if (ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E)
            badDate = ret;
        else
            return ret;
    }

    if (cert->srcIdx != cert->sigIndex)
        cert->srcIdx =  cert->sigIndex;

    if ((ret = GetAlgoId(cert->source, &cert->srcIdx, &confirmOID)) < 0)
        return ret;

    if ((ret = GetSignature(cert)) < 0)
        return ret;

    if (confirmOID != cert->signatureOID)
        return ASN_SIG_OID_E;

    if (verify && type != CA_TYPE) {
        while (signers) {
            if (XMEMCMP(cert->issuerHash, signers->hash, SHA_DIGEST_SIZE)
                       == 0) {
                /* other confirm */
                if (!ConfirmSignature(cert, signers->publicKey,
                                      signers->pubKeySize, signers->keyOID))
                    return ASN_SIG_CONFIRM_E;
                else {
                    confirm = 1;
                    break;
                }
            }
            signers = signers->next;
        }
        if (!confirm)
            return ASN_SIG_CONFIRM_E;
    }
    if (badDate != 0)
        return badDate;

    return 0;
}


Signer* MakeSigner(void* heap)
{
    Signer* signer = (Signer*) XMALLOC(sizeof(Signer), heap,
                                       DYNAMIC_TYPE_SIGNER);
    if (signer) {
        signer->name      = 0;
        signer->publicKey = 0;
        signer->next      = 0;
    }

    return signer;
}


void FreeSigners(Signer* signer, void* heap)
{
    Signer* next = signer;

    while( (signer = next) ) {
        next = signer->next;
        XFREE(signer->name, heap, DYNAMIC_TYPE_SUBJECT_CN);
        XFREE(signer->publicKey, heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(signer, heap, DYNAMIC_TYPE_SIGNER);
    }
}


void CTaoCryptErrorString(int error, char* buffer)
{
    const int max = MAX_ERROR_SZ;   /* shorthand */

#ifdef NO_ERROR_STRINGS

    XSTRNCPY(buffer, "no support for error strings built in", max);

#else

    switch (error) {

    case OPEN_RAN_E :        
        XSTRNCPY(buffer, "opening random device error", max);
        break;

    case READ_RAN_E :
        XSTRNCPY(buffer, "reading random device error", max);
        break;

    case WINCRYPT_E :
        XSTRNCPY(buffer, "windows crypt init error", max);
        break;

    case CRYPTGEN_E : 
        XSTRNCPY(buffer, "windows crypt generation error", max);
        break;

    case RAN_BLOCK_E : 
        XSTRNCPY(buffer, "random device read would block error", max);
        break;

    case MP_INIT_E :
        XSTRNCPY(buffer, "mp_init error state", max);
        break;

    case MP_READ_E :
        XSTRNCPY(buffer, "mp_read error state", max);
        break;

    case MP_EXPTMOD_E :
        XSTRNCPY(buffer, "mp_exptmod error state", max);
        break;

    case MP_TO_E :
        XSTRNCPY(buffer, "mp_to_xxx error state, can't convert", max);
        break;

    case MP_SUB_E :
        XSTRNCPY(buffer, "mp_sub error state, can't subtract", max);
        break;

    case MP_ADD_E :
        XSTRNCPY(buffer, "mp_add error state, can't add", max);
        break;

    case MP_MUL_E :
        XSTRNCPY(buffer, "mp_mul error state, can't multiply", max);
        break;

    case MP_MULMOD_E :
        XSTRNCPY(buffer, "mp_mulmod error state, can't multiply mod", max);
        break;

    case MP_MOD_E :
        XSTRNCPY(buffer, "mp_mod error state, can't mod", max);
        break;

    case MP_INVMOD_E :
        XSTRNCPY(buffer, "mp_invmod error state, can't inv mod", max);
        break; 
        
    case MP_CMP_E :
        XSTRNCPY(buffer, "mp_cmp error state", max);
        break; 
        
    case MEMORY_E :
        XSTRNCPY(buffer, "out of memory error", max);
        break;

    case RSA_WRONG_TYPE_E :
        XSTRNCPY(buffer, "RSA wrong block type for RSA function", max);
        break; 

    case RSA_BUFFER_E :
        XSTRNCPY(buffer, "RSA buffer error, output too small or input too big",
                max);
        break; 

    case BUFFER_E :
        XSTRNCPY(buffer, "Buffer error, output too small or input too big", max);
        break; 

    case ALGO_ID_E :
        XSTRNCPY(buffer, "Setting Cert AlogID error", max);
        break; 

    case PUBLIC_KEY_E :
        XSTRNCPY(buffer, "Setting Cert Public Key error", max);
        break; 

    case DATE_E :
        XSTRNCPY(buffer, "Setting Cert Date validity error", max);
        break; 

    case SUBJECT_E :
        XSTRNCPY(buffer, "Setting Cert Subject name error", max);
        break; 

    case ISSUER_E :
        XSTRNCPY(buffer, "Setting Cert Issuer name error", max);
        break; 

    case ASN_PARSE_E :
        XSTRNCPY(buffer, "ASN parsing error, invalid input", max);
        break;

    case ASN_VERSION_E :
        XSTRNCPY(buffer, "ASN version error, invalid number", max);
        break;

    case ASN_GETINT_E :
        XSTRNCPY(buffer, "ASN get big int error, invalid data", max);
        break;

    case ASN_RSA_KEY_E :
        XSTRNCPY(buffer, "ASN key init error, invalid input", max);
        break;

    case ASN_OBJECT_ID_E :
        XSTRNCPY(buffer, "ASN object id error, invalid id", max);
        break;

    case ASN_TAG_NULL_E :
        XSTRNCPY(buffer, "ASN tag error, not null", max);
        break;

    case ASN_EXPECT_0_E :
        XSTRNCPY(buffer, "ASN expect error, not zero", max);
        break;

    case ASN_BITSTR_E :
        XSTRNCPY(buffer, "ASN bit string error, wrong id", max);
        break;

    case ASN_UNKNOWN_OID_E :
        XSTRNCPY(buffer, "ASN oid error, unknown sum id", max);
        break;

    case ASN_DATE_SZ_E :
        XSTRNCPY(buffer, "ASN date error, bad size", max);
        break;

    case ASN_BEFORE_DATE_E :
        XSTRNCPY(buffer, "ASN date error, current date before", max);
        break;

    case ASN_AFTER_DATE_E :
        XSTRNCPY(buffer, "ASN date error, current date after", max);
        break;

    case ASN_SIG_OID_E :
        XSTRNCPY(buffer, "ASN signature error, mismatched oid", max);
        break;

    case ASN_TIME_E :
        XSTRNCPY(buffer, "ASN time error, unkown time type", max);
        break;

    case ASN_INPUT_E :
        XSTRNCPY(buffer, "ASN input error, not enough data", max);
        break;

    case ASN_SIG_CONFIRM_E :
        XSTRNCPY(buffer, "ASN sig error, confirm failure", max);
        break;

    case ASN_SIG_HASH_E :
        XSTRNCPY(buffer, "ASN sig error, unsupported hash type", max);
        break;

    case ASN_SIG_KEY_E :
        XSTRNCPY(buffer, "ASN sig error, unsupported key type", max);
        break;

    case ASN_DH_KEY_E :
        XSTRNCPY(buffer, "ASN key init error, invalid input", max);
        break;

    case ASN_NTRU_KEY_E :
        XSTRNCPY(buffer, "ASN NTRU key decode error, invalid input", max);
        break;

    case ECC_BAD_ARG_E :
        XSTRNCPY(buffer, "ECC input argument wrong type, invalid input", max);
        break;

    case ASN_ECC_KEY_E :
        XSTRNCPY(buffer, "ECC ASN1 bad key data, invalid input", max);
        break;

    case ECC_CURVE_OID_E :
        XSTRNCPY(buffer, "ECC curve sum OID unsupported, invalid input", max);
        break;

    default:
        XSTRNCPY(buffer, "unknown error number", max);

    }

#endif /* NO_ERROR_STRINGS */

}


#if defined(CYASSL_KEY_GEN) || defined(CYASSL_CERT_GEN)

static int SetMyVersion(word32 version, byte* output, int header)
{
    int i = 0;

    if (header) {
        output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
        output[i++] = ASN_BIT_STRING;
    }
    output[i++] = ASN_INTEGER;
    output[i++] = 0x01;
    output[i++] = version;

    return i;
}


int DerToPem(const byte* der, word32 derSz, byte* output, word32 outSz,
             int type)
{
    char header[80];
    char footer[80];

    int headerLen;
    int footerLen;
    int i;
    int outLen;   /* return length or error */

    if (type == CERT_TYPE) {
        XSTRNCPY(header, "-----BEGIN CERTIFICATE-----\n", sizeof(header));
        XSTRNCPY(footer, "-----END CERTIFICATE-----\n", sizeof(footer));
    } else {
        XSTRNCPY(header, "-----BEGIN RSA PRIVATE KEY-----\n", sizeof(header));
        XSTRNCPY(footer, "-----END RSA PRIVATE KEY-----\n", sizeof(footer));
    }

    headerLen = XSTRLEN(header);
    footerLen = XSTRLEN(footer);

    if (!der || !output)
        return -1;

    /* don't even try if outSz too short */
    if (outSz < headerLen + footerLen + derSz)
        return -1;

    /* header */
    XMEMCPY(output, header, headerLen);
    i = headerLen;

    /* body */
    outLen = outSz;  /* input to Base64Encode */
    if (Base64Encode(der, derSz, output + i, (word32*)&outLen) < 0)
        return -1;
    i += outLen;

    /* footer */
    if ( (i + footerLen) > (int)outSz)
        return -1;
    XMEMCPY(output + i, footer, footerLen);

    return outLen + headerLen + footerLen;
}


#endif /* CYASSL_KEY_GEN || CYASSL_CERT_GEN */


#ifdef CYASSL_KEY_GEN


static mp_int* GetRsaInt(RsaKey* key, int index)
{
    if (index == 0)
        return &key->n;
    if (index == 1)
        return &key->e;
    if (index == 2)
        return &key->d;
    if (index == 3)
        return &key->p;
    if (index == 4)
        return &key->q;
    if (index == 5)
        return &key->dP;
    if (index == 6)
        return &key->dQ;
    if (index == 7)
        return &key->u;

    return NULL;
}


/* Convert RsaKey key to DER format, write to output (inLen), return bytes
   written */
int RsaKeyToDer(RsaKey* key, byte* output, word32 inLen)
{
    word32 seqSz, verSz, rawLen, intTotalLen = 0;
    word32 sizes[RSA_INTS];
    int    i, j, outLen;

    byte seq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];
    byte tmps[RSA_INTS][MAX_RSA_INT_SZ];

    if (!key || !output)
        return -1;

    if (key->type != RSA_PRIVATE)
        return -1;

    /* write all big ints from key to DER tmps */
    for (i = 0; i < RSA_INTS; i++) {
        mp_int* keyInt = GetRsaInt(key, i);
        rawLen = mp_unsigned_bin_size(keyInt);

        tmps[i][0] = ASN_INTEGER;
        sizes[i] = SetLength(rawLen, tmps[i] + 1) + 1;  /* int tag */

        if ( (sizes[i] + rawLen) < sizeof(tmps[i])) {
            int err = mp_to_unsigned_bin(keyInt, tmps[i] + sizes[i]);
            if (err == MP_OKAY) {
                sizes[i] += rawLen;
                intTotalLen += sizes[i];
            }
            else
                return err;
        }
        else
            return -1;
    }

    /* make headers */
    verSz = SetMyVersion(0, ver, FALSE);
    seqSz = SetSequence(verSz + intTotalLen, seq);

    outLen = seqSz + verSz + intTotalLen;
    if (outLen > (int)inLen)
        return -1;

    /* write to output */
    XMEMCPY(output, seq, seqSz);
    j = seqSz;
    XMEMCPY(output + j, ver, verSz);
    j += verSz;

    for (i = 0; i < RSA_INTS; i++) {
        XMEMCPY(output + j, tmps[i], sizes[i]);
        j += sizes[i];
    }

    return outLen;
}

#endif /* CYASSL_KEY_GEN */


#ifdef CYASSL_CERT_GEN

/* Initialize and Set Certficate defaults:
   version    = 3 (0x2)
   serial     = 0
   sigType    = MD5_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
*/
void InitCert(Cert* cert)
{
    cert->version    = 2;   /* version 3 is hex 2 */
    cert->sigType    = MD5wRSA;
    cert->daysValid  = 500;
    cert->selfSigned = 1;
    cert->bodySz     = 0;
    cert->keyType    = RSA_KEY;
    XMEMSET(cert->serial, 0, SERIAL_SIZE);

    cert->issuer.country[0] = '\0';
    cert->issuer.state[0] = '\0';
    cert->issuer.locality[0] = '\0';
    cert->issuer.sur[0] = '\0';
    cert->issuer.org[0] = '\0';
    cert->issuer.unit[0] = '\0';
    cert->issuer.commonName[0] = '\0';
    cert->issuer.email[0] = '\0';

    cert->subject.country[0] = '\0';
    cert->subject.state[0] = '\0';
    cert->subject.locality[0] = '\0';
    cert->subject.sur[0] = '\0';
    cert->subject.org[0] = '\0';
    cert->subject.unit[0] = '\0';
    cert->subject.commonName[0] = '\0';
    cert->subject.email[0] = '\0';
}


/* DER encoded x509 Certificate */
typedef struct DerCert {
    byte size[MAX_LENGTH_SZ];          /* length encoded */
    byte version[MAX_VERSION_SZ];      /* version encoded */
    byte serial[SERIAL_SIZE + MAX_LENGTH_SZ]; /* serial number encoded */
    byte sigAlgo[MAX_ALGO_SZ];         /* signature algo encoded */
    byte issuer[ASN_NAME_MAX];         /* issuer  encoded */
    byte subject[ASN_NAME_MAX];        /* subject encoded */
    byte validity[MAX_DATE_SIZE*2 + MAX_SEQ_SZ*2];  /* before and after dates */
    byte publicKey[MAX_PUBLIC_KEY_SZ]; /* rsa / ntru public key encoded */
    int  sizeSz;                       /* encoded size length */
    int  versionSz;                    /* encoded version length */
    int  serialSz;                     /* encoded serial length */
    int  sigAlgoSz;                    /* enocded sig alog length */
    int  issuerSz;                     /* encoded issuer length */
    int  subjectSz;                    /* encoded subject length */
    int  validitySz;                   /* encoded validity length */
    int  publicKeySz;                  /* encoded public key length */
    int  total;                        /* total encoded lengths */
} DerCert;


/* Write a set header to output */
static word32 SetSet(word32 len, byte* output)
{
    output[0] = ASN_SET | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}


/* Write a serial number to output */
static int SetSerial(const byte* serial, byte* output)
{
    int length = 0;

    output[length++] = ASN_INTEGER;
    length += SetLength(SERIAL_SIZE, &output[length]);
    XMEMCPY(&output[length], serial, SERIAL_SIZE);

    return length + SERIAL_SIZE;
}


/* Write a public RSA key to output */
static int SetPublicKey(byte* output, RsaKey* key)
{
    byte n[MAX_RSA_INT_SZ];
    byte e[MAX_RSA_E_SZ];
    byte algo[MAX_ALGO_SZ];
    byte seq[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ + 1];  /* trailing 0 */
    int  nSz;
    int  eSz;
    int  algoSz;
    int  seqSz;
    int  lenSz;
    int  idx;
    int  rawLen;

    /* n */
    rawLen = mp_unsigned_bin_size(&key->n);
    n[0] = ASN_INTEGER;
    nSz  = SetLength(rawLen, n + 1) + 1;  /* int tag */

    if ( (nSz + rawLen) < sizeof(n)) {
        int err = mp_to_unsigned_bin(&key->n, n + nSz);
        if (err == MP_OKAY)
            nSz += rawLen;
        else
            return MP_TO_E;
    }
    else
        return BUFFER_E;

    /* e */
    rawLen = mp_unsigned_bin_size(&key->e);
    e[0] = ASN_INTEGER;
    eSz  = SetLength(rawLen, e + 1) + 1;  /* int tag */

    if ( (eSz + rawLen) < sizeof(e)) {
        int err = mp_to_unsigned_bin(&key->e, e + eSz);
        if (err == MP_OKAY)
            eSz += rawLen;
        else
            return MP_TO_E;
    }
    else
        return BUFFER_E;

    /* headers */
    algoSz = SetAlgoID(RSAk, algo, keyType);
    seqSz  = SetSequence(nSz + eSz, seq);
    lenSz  = SetLength(seqSz + nSz + eSz + 1, len);
    len[lenSz++] = 0;   /* trailing 0 */

    /* write */
    idx = SetSequence(nSz + eSz + seqSz + lenSz + 1 + algoSz, output);
        /* 1 is for ASN_BIT_STRING */
    /* algo */
    XMEMCPY(output + idx, algo, algoSz);
    idx += algoSz;
    /* bit string */
    output[idx++] = ASN_BIT_STRING;
    /* length */
    XMEMCPY(output + idx, len, lenSz);
    idx += lenSz;
    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx += seqSz;
    /* n */
    XMEMCPY(output + idx, n, nSz);
    idx += nSz;
    /* e */
    XMEMCPY(output + idx, e, eSz);
    idx += eSz;

    return idx;
}


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
    
    output[i] = 'Z';  /* Zulu profiel */
}


/* Set Date validity from now until now + daysValid */
static int SetValidity(byte* output, int daysValid)
{
    byte before[MAX_DATE_SIZE];
    byte  after[MAX_DATE_SIZE];

    int beforeSz;
    int afterSz;
    int seqSz;

    time_t     ticks;
    struct tm* now;
    struct tm  local;

    ticks = XTIME(0);
    now   = XGMTIME(&ticks);

    /* before now */
    local = *now;
    before[0] = ASN_GENERALIZED_TIME;
    beforeSz  = SetLength(ASN_GEN_TIME_SZ, before + 1) + 1;  /* gen tag */

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
    mktime(&local);

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
    int  totalLen;               /* total encodeding length */
    int  type;                   /* type of name */
    int  used;                   /* are we actually using this one */
    byte encoded[NAME_SIZE * 2]; /* encoding */
} EncodedName;


/* Get Which Name from index */
static const char* GetOneName(CertName* name, int index)
{
    switch (index) {
    case 0:
       return name->country;
       break;
    case 1:
       return name->state;
       break;
    case 2:
       return name->locality;
       break;
    case 3:
       return name->sur;
       break;
    case 4:
       return name->org;
       break;
    case 5:
       return name->unit;
       break;
    case 6:
       return name->commonName;
       break;
    case 7:
       return name->email;
       break;
    default:
       return 0;
    }

    return 0;
}


/* Get ASN Name from index */
static byte GetNameId(int index)
{
    switch (index) {
    case 0:
       return ASN_COUNTRY_NAME;
       break;
    case 1:
       return ASN_STATE_NAME;
       break;
    case 2:
       return ASN_LOCALITY_NAME;
       break;
    case 3:
       return ASN_SUR_NAME;
       break;
    case 4:
       return ASN_ORG_NAME;
       break;
    case 5:
       return ASN_ORGUNIT_NAME;
       break;
    case 6:
       return ASN_COMMON_NAME;
       break;
    case 7:
       /* email uses different id type */
       return 0;
       break;
    default:
       return 0;
    }

    return 0;
}


/* encode CertName into output, return total bytes written */
static int SetName(byte* output, CertName* name)
{
    int         totalBytes = 0, i, idx;
    EncodedName names[NAME_ENTRIES];

    for (i = 0; i < NAME_ENTRIES; i++) {
        const char* nameStr = GetOneName(name, i);
        if (nameStr) {
            /* bottom up */
            byte firstLen[MAX_LENGTH_SZ];
            byte secondLen[MAX_LENGTH_SZ];
            byte sequence[MAX_SEQ_SZ];
            byte set[MAX_SET_SZ];

            int email = i == (NAME_ENTRIES - 1) ? 1 : 0;
            int strLen  = XSTRLEN(nameStr);
            int thisLen = strLen;
            int firstSz, secondSz, seqSz, setSz;

            if (strLen == 0) { /* no user data for this item */
                names[i].used = 0;
                continue;
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

            if (thisLen > sizeof(names[i].encoded))
                return BUFFER_E;

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
                idx += sizeof(EMAIL_OID);
            }
            else {
                /* joint id */
                names[i].encoded[idx++] = 0x55;
                names[i].encoded[idx++] = 0x04;
                /* id type */
                names[i].encoded[idx++] = GetNameId(i);
                /* str type */
                names[i].encoded[idx++] = 0x13;
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
    if (totalBytes > ASN_NAME_MAX)
        return BUFFER_E;

    for (i = 0; i < NAME_ENTRIES; i++) {
        if (names[i].used) {
            XMEMCPY(output + idx, names[i].encoded, names[i].totalLen);
            idx += names[i].totalLen;
        }
    }
    return totalBytes;
}


/* encode info from cert into DER enocder format */
static int EncodeCert(Cert* cert, DerCert* der, RsaKey* rsaKey, RNG* rng,
                      const byte* ntruKey, word16 ntruSz)
{
    /* version */
    der->versionSz = SetMyVersion(cert->version, der->version, TRUE);

    /* serial number */
    RNG_GenerateBlock(rng, cert->serial, SERIAL_SIZE);
    cert->serial[0] = 0x01;   /* ensure positive */
    der->serialSz  = SetSerial(cert->serial, der->serial);

    /* signature algo */
    der->sigAlgoSz = SetAlgoID(cert->sigType, der->sigAlgo, sigType);
    if (der->sigAlgoSz == 0)
        return ALGO_ID_E;

    /* public key */
    if (cert->keyType == RSA_KEY) {
        der->publicKeySz = SetPublicKey(der->publicKey, rsaKey);
        if (der->publicKeySz == 0)
            return PUBLIC_KEY_E;
    }
    else {
#ifdef HAVE_NTRU
        word32 rc;
        word16 encodedSz;

        rc  = crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo( ntruSz,
                                              ntruKey, &encodedSz, NULL);
        if (rc != NTRU_OK)
            return PUBLIC_KEY_E;
        if (encodedSz > MAX_PUBLIC_KEY_SZ)
            return PUBLIC_KEY_E;

        rc  = crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo( ntruSz,
                              ntruKey, &encodedSz, der->publicKey);
        if (rc != NTRU_OK)
            return PUBLIC_KEY_E;

        der->publicKeySz = encodedSz;
#endif
    }

    /* date validity */
    der->validitySz = SetValidity(der->validity, cert->daysValid);
    if (der->validitySz == 0)
        return DATE_E;

    /* subject name */
    der->subjectSz = SetName(der->subject, &cert->subject);
    if (der->subjectSz == 0)
        return SUBJECT_E;

    /* issuer name */
    der->issuerSz = SetName(der->issuer, cert->selfSigned ?
             &cert->subject : &cert->issuer);
    if (der->issuerSz == 0)
        return ISSUER_E;

    der->total = der->versionSz + der->serialSz + der->sigAlgoSz +
        der->publicKeySz + der->validitySz + der->subjectSz + der->issuerSz;

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

    return idx;
}


/* Make MD5wRSA signature from buffer (sz), write to sig (sigSz) */
static int MakeSignature(const byte* buffer, int sz, byte* sig, int sigSz,
                         RsaKey* key, RNG* rng)
{
    byte    digest[SHA_DIGEST_SIZE];     /* max size */
    byte    encSig[MAX_ENCODED_DIG_SZ + MAX_ALGO_SZ + MAX_SEQ_SZ];
    int     encSigSz, digestSz, hashType;
    Md5     md5;                         /* md5 for now */

    InitMd5(&md5);
    Md5Update(&md5, buffer, sz);
    Md5Final(&md5, digest);
    digestSz = MD5_DIGEST_SIZE;
    hashType = MD5h;

    /* signature */
    encSigSz = EncodeSignature(encSig, digest, digestSz, hashType);
    return RsaSSL_Sign(encSig, encSigSz, sig, sigSz, key, rng);
}


/* add signature to end of buffer, size of buffer assumed checked, return
   new length */
static int AddSignature(byte* buffer, int bodySz, const byte* sig, int sigSz)
{
    byte seq[MAX_SEQ_SZ];
    int  idx = bodySz, seqSz;

    /* algo */
    idx += SetAlgoID(MD5wRSA, buffer + idx, sigType);
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
                   RsaKey* rsaKey, RNG* rng, const byte* ntruKey, word16 ntruSz)
{
    DerCert der;
    int     ret;

    cert->keyType = rsaKey ? RSA_KEY : NTRU_KEY;
    ret = EncodeCert(cert, &der, rsaKey, rng, ntruKey, ntruSz);
    if (ret != 0)
        return ret;

    if (der.total + MAX_SEQ_SZ * 2 > (int)derSz)
        return BUFFER_E;

    return cert->bodySz = WriteCertBody(&der, derBuffer);
}


/* Make an x509 Certificate v3 RSA from cert input, write to buffer */
int MakeCert(Cert* cert, byte* derBuffer, word32 derSz, RsaKey* rsaKey,RNG* rng)
{
    return MakeAnyCert(cert, derBuffer, derSz, rsaKey, rng, NULL, 0);
}


#ifdef HAVE_NTRU

int  MakeNtruCert(Cert* cert, byte* derBuffer, word32 derSz,
                  const byte* ntruKey, word16 keySz, RNG* rng)
{
    return MakeAnyCert(cert, derBuffer, derSz, NULL, rng, ntruKey, keySz);
}

#endif /* HAVE_NTRU */


int SignCert(Cert* cert, byte* buffer, word32 buffSz, RsaKey* key, RNG* rng)
{
    byte    sig[MAX_ENCODED_SIG_SZ];
    int     sigSz;
    int     bodySz = cert->bodySz;

    if (bodySz < 0)
        return bodySz;

    sigSz  = MakeSignature(buffer, bodySz, sig, sizeof(sig), key, rng);
    if (sigSz < 0)
        return sigSz; 

    if (bodySz + MAX_SEQ_SZ * 2 + sigSz > (int)buffSz)
        return BUFFER_E; 

    return AddSignature(buffer, bodySz, sig, sigSz);
}


int MakeSelfCert(Cert* cert, byte* buffer, word32 buffSz, RsaKey* key, RNG* rng)
{
    int ret = MakeCert(cert, buffer, buffSz, key, rng);

    if (ret < 0)
        return ret;

    return SignCert(cert, buffer, buffSz, key, rng);
}


/* forward from CyaSSL */
int CyaSSL_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz);

#ifndef NO_FILESYSTEM

int SetIssuer(Cert* cert, const char* issuerCertFile)
{
    DecodedCert decoded;
    byte        der[8192];
    int         derSz = CyaSSL_PemCertToDer(issuerCertFile, der, sizeof(der));
    int         ret;
    int         sz;

    if (derSz < 0)
        return derSz;

    cert->selfSigned = 0;

    InitDecodedCert(&decoded, der, 0);
    ret = ParseCertRelative(&decoded, derSz, CA_TYPE, NO_VERIFY, 0);

    if (ret < 0)
        return ret;

    if (decoded.subjectCN) {
        sz = (decoded.subjectCNLen < NAME_SIZE) ? decoded.subjectCNLen :
                                                  NAME_SIZE - 1;
        strncpy(cert->issuer.commonName, decoded.subjectCN, NAME_SIZE);
        cert->issuer.commonName[sz] = 0;
    }
    if (decoded.subjectC) {
        sz = (decoded.subjectCLen < NAME_SIZE) ? decoded.subjectCLen :
                                                 NAME_SIZE - 1;
        strncpy(cert->issuer.country, decoded.subjectC, NAME_SIZE);
        cert->issuer.country[sz] = 0;
    }
    if (decoded.subjectST) {
        sz = (decoded.subjectSTLen < NAME_SIZE) ? decoded.subjectSTLen :
                                                  NAME_SIZE - 1;
        strncpy(cert->issuer.state, decoded.subjectST, NAME_SIZE);
        cert->issuer.state[sz] = 0;
    }
    if (decoded.subjectL) {
        sz = (decoded.subjectLLen < NAME_SIZE) ? decoded.subjectLLen :
                                                 NAME_SIZE - 1;
        strncpy(cert->issuer.locality, decoded.subjectL, NAME_SIZE);
        cert->issuer.locality[sz] = 0;
    }
    if (decoded.subjectO) {
        sz = (decoded.subjectOLen < NAME_SIZE) ? decoded.subjectOLen :
                                                 NAME_SIZE - 1;
        strncpy(cert->issuer.org, decoded.subjectO, NAME_SIZE);
        cert->issuer.org[sz] = 0;
    }
    if (decoded.subjectOU) {
        sz = (decoded.subjectOULen < NAME_SIZE) ? decoded.subjectOULen :
                                                  NAME_SIZE - 1;
        strncpy(cert->issuer.unit, decoded.subjectOU, NAME_SIZE);
        cert->issuer.unit[sz] = 0;
    }
    if (decoded.subjectSN) {
        sz = (decoded.subjectSNLen < NAME_SIZE) ? decoded.subjectSNLen :
                                                  NAME_SIZE - 1;
        strncpy(cert->issuer.sur, decoded.subjectSN, NAME_SIZE);
        cert->issuer.sur[sz] = 0;
    }
    if (decoded.subjectEmail) {
        sz = (decoded.subjectEmailLen < NAME_SIZE) ? decoded.subjectEmailLen :
                                                     NAME_SIZE - 1;
        strncpy(cert->issuer.email, decoded.subjectEmail, NAME_SIZE);
        cert->issuer.email[sz] = 0;
    }

    FreeDecodedCert(&decoded);

    return 0;
}

#endif /* NO_FILESYSTEM */
#endif /* CYASSL_CERT_GEN */


#ifdef HAVE_ECC

/* Der Eoncde r & s ints into out, outLen is (in/out) size */
int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    word32 rSz;                           /* encoding size */
    word32 sSz;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */

    int rLen = mp_unsigned_bin_size(r);   /* big int size */
    int sLen = mp_unsigned_bin_size(s);
    int err;

    if (*outLen < (rLen + sLen + headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return -1;

    idx = SetSequence(rLen + sLen + headerSz, out);

    /* store r */
    out[idx++] = ASN_INTEGER;
    rSz = SetLength(rLen, &out[idx]);
    idx += rSz;
    err = mp_to_unsigned_bin(r, &out[idx]);
    if (err != MP_OKAY) return err;
    idx += rLen;

    /* store s */
    out[idx++] = ASN_INTEGER;
    sSz = SetLength(sLen, &out[idx]);
    idx += sSz;
    err = mp_to_unsigned_bin(s, &out[idx]);
    if (err != MP_OKAY) return err;
    idx += sLen;

    *outLen = idx;

    return 0;
}


/* Der Decode ECC-DSA Signautre, r & s stored as big ints */
int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len) < 0)
        return ASN_ECC_KEY_E;

    if ((word32)len > (sigLen - idx))
        return ASN_ECC_KEY_E;

    if (GetInt(r, sig, &idx) < 0)
        return ASN_ECC_KEY_E;

    if (GetInt(s, sig, &idx) < 0)
        return ASN_ECC_KEY_E;

    return 0;
}


int EccPrivateKeyDecode(const byte* input, word32* inOutIdx, ecc_key* key,
                        word32 inSz)
{
    word32 begin = *inOutIdx;
    word32 oid = 0;
    int    version, length;
    int    privSz, pubSz;
    byte   b;
    byte   priv[ECC_MAXSIZE];
    byte   pub[ECC_MAXSIZE * 2 + 1]; /* public key has two parts plus header */

    if (GetSequence(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    if ((word32)length > (inSz - (*inOutIdx - begin)))
        return ASN_INPUT_E;

    if (GetMyVersion(input, inOutIdx, &version) < 0)
        return ASN_PARSE_E;

    b = input[*inOutIdx];
    *inOutIdx += 1;

    /* priv type */
    if (b != 4 && b != 6 && b != 7) 
        return ASN_PARSE_E;

    if (GetLength(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    /* priv key */
    privSz = length;
    XMEMCPY(priv, &input[*inOutIdx], privSz);
    *inOutIdx += length;

    /* prefix 0 */
    b = input[*inOutIdx];
    *inOutIdx += 1;

    if (GetLength(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    /* object id */
    b = input[*inOutIdx];
    *inOutIdx += 1;
    
    if (b != ASN_OBJECT_ID) 
        return ASN_OBJECT_ID_E;

    if (GetLength(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    while(length--) {
        oid += input[*inOutIdx];
        *inOutIdx += 1;
    }
    if (CheckCurve(oid) < 0)
        return ECC_CURVE_OID_E;
    
    /* prefix 1 */
    b = input[*inOutIdx];
    *inOutIdx += 1;

    if (GetLength(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;

    /* key header */
    b = input[*inOutIdx];
    *inOutIdx += 1;
    if (b != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(input, inOutIdx, &length) < 0)
        return ASN_PARSE_E;
    b = input[*inOutIdx];
    *inOutIdx += 1;
    if (b != 0x00)
        return ASN_EXPECT_0_E;

    pubSz = length - 1;  /* null prefix */
    XMEMCPY(pub, &input[*inOutIdx], pubSz);

    *inOutIdx += length;
    
    return ecc_import_private_key(priv, privSz, pub, pubSz, key);
}

#endif  /* HAVE_ECC */
