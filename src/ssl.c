/* ssl.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef HAVE_ERRNO_H 
    #include <errno.h>
#endif

#define TRUE  1
#define FALSE 0

#include <cyassl/ssl.h>
#include <cyassl/internal.h>
#include <cyassl/error.h>
#include <cyassl/ctaocrypt/coding.h>

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    #include <cyassl/openssl/evp.h>
#endif

#ifdef OPENSSL_EXTRA
    /* openssl headers begin */
    #include <cyassl/openssl/hmac.h>
    #include <cyassl/openssl/crypto.h>
    #include <cyassl/openssl/des.h>
    /* openssl headers end, cyassl internal headers next */
    #include <cyassl/ctaocrypt/hmac.h>
    #include <cyassl/ctaocrypt/random.h>
    #include <cyassl/ctaocrypt/des3.h>
    #include <cyassl/ctaocrypt/md4.h>
    #include <cyassl/ctaocrypt/md5.h>
#endif


#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */



CYASSL_CTX* CyaSSL_CTX_new(CYASSL_METHOD* method)
{
    CYASSL_CTX* ctx = NULL;

    CYASSL_ENTER("CYASSL_CTX_new");

    if (method == NULL)
        return ctx;

    ctx = (CYASSL_CTX*) XMALLOC(sizeof(CYASSL_CTX), 0, DYNAMIC_TYPE_CTX);
    if (ctx) {
        if (InitSSL_Ctx(ctx, method) < 0) {
            CYASSL_MSG("Init CTX failed");
            CyaSSL_CTX_free(ctx);
            ctx = NULL;
        }
    }

    CYASSL_LEAVE("CYASSL_CTX_new", 0);
    return ctx;
}


void CyaSSL_CTX_free(CYASSL_CTX* ctx)
{
    CYASSL_ENTER("SSL_CTX_free");
    if (ctx)
        FreeSSL_Ctx(ctx);
    CYASSL_LEAVE("SSL_CTX_free", 0);
}


CYASSL* CyaSSL_new(CYASSL_CTX* ctx)
{
    CYASSL* ssl = NULL;

    CYASSL_ENTER("SSL_new");

    if (ctx == NULL)
        return ssl;

    ssl = (CYASSL*) XMALLOC(sizeof(CYASSL), ctx->heap,DYNAMIC_TYPE_SSL);
    if (ssl)
        if (InitSSL(ssl, ctx) < 0) {
            FreeSSL(ssl);
            ssl = 0;
        }

    CYASSL_LEAVE("SSL_new", 0);
    return ssl;
}


void CyaSSL_free(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_free");
    if (ssl)
        FreeSSL(ssl);
    CYASSL_LEAVE("SSL_free", 0);
}


int CyaSSL_set_fd(CYASSL* ssl, int fd)
{
    CYASSL_ENTER("SSL_set_fd");
    ssl->rfd = fd;      /* not used directly to allow IO callbacks */
    ssl->wfd = fd;

    ssl->IOCB_ReadCtx  = &ssl->rfd;
    ssl->IOCB_WriteCtx = &ssl->wfd;

    CYASSL_LEAVE("SSL_set_fd", SSL_SUCCESS);
    return SSL_SUCCESS;
}


int CyaSSL_get_fd(const CYASSL* ssl)
{
    CYASSL_ENTER("SSL_get_fd");
    CYASSL_LEAVE("SSL_get_fd", ssl->rfd);
    return ssl->rfd;
}


int CyaSSL_negotiate(CYASSL* ssl)
{
    int err = SSL_FATAL_ERROR;

    CYASSL_ENTER("CyaSSL_negotiate");
#ifndef NO_CYASSL_SERVER
    if (ssl->options.side == SERVER_END)
        err = CyaSSL_accept(ssl);
#endif

#ifndef NO_CYASSL_CLIENT
    if (ssl->options.side == CLIENT_END)
        err = CyaSSL_connect(ssl);
#endif

    CYASSL_LEAVE("CyaSSL_negotiate", err);

    if (err == SSL_SUCCESS)
        return 0;
    else
        return err;
}


/* server Diffie-Hellman parameters */
int CyaSSL_SetTmpDH(CYASSL* ssl, const unsigned char* p, int pSz,
                    const unsigned char* g, int gSz)
{
    byte havePSK = 0;

    CYASSL_ENTER("CyaSSL_SetTmpDH");
    if (ssl == NULL || p == NULL || g == NULL) return BAD_FUNC_ARG;

    if (ssl->options.side != SERVER_END)
        return SIDE_ERROR;

    if (ssl->buffers.serverDH_P.buffer && ssl->buffers.weOwnDH)
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_G.buffer && ssl->buffers.weOwnDH)
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);

    ssl->buffers.weOwnDH = 1;  /* SSL owns now */
    ssl->buffers.serverDH_P.buffer = (byte*)XMALLOC(pSz, ssl->ctx->heap,
                                                    DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_P.buffer == NULL)
        return MEMORY_E;

    ssl->buffers.serverDH_G.buffer = (byte*)XMALLOC(gSz, ssl->ctx->heap,
                                                    DYNAMIC_TYPE_DH);
    if (ssl->buffers.serverDH_G.buffer == NULL) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->ctx->heap, DYNAMIC_TYPE_DH);
        return MEMORY_E;
    }

    ssl->buffers.serverDH_P.length = pSz;
    ssl->buffers.serverDH_G.length = gSz;

    XMEMCPY(ssl->buffers.serverDH_P.buffer, p, pSz);
    XMEMCPY(ssl->buffers.serverDH_G.buffer, g, gSz);

    ssl->options.haveDH = 1;
    #ifndef NO_PSK
        havePSK = ssl->options.havePSK;
    #endif
    InitSuites(&ssl->suites, ssl->version, ssl->options.haveDH,
               havePSK, ssl->options.haveNTRU, ssl->options.haveECDSA,
               ssl->ctx->method->side);

    CYASSL_LEAVE("CyaSSL_SetTmpDH", 0);
    return 0;
}


int CyaSSL_write(CYASSL* ssl, const void* data, int sz)
{
    int ret;

    CYASSL_ENTER("SSL_write()");

#ifdef HAVE_ERRNO_H 
    errno = 0;
#endif

    ret = SendData(ssl, data, sz);

    CYASSL_LEAVE("SSL_write()", ret);

    if (ret < 0)
        return SSL_FATAL_ERROR;
    else
        return ret;
}


int CyaSSL_read(CYASSL* ssl, void* data, int sz)
{
    int ret; 

    CYASSL_ENTER("SSL_read()");

#ifdef HAVE_ERRNO_H 
        errno = 0;
#endif

    ret = ReceiveData(ssl, (byte*)data, min(sz, OUTPUT_RECORD_SIZE));

    CYASSL_LEAVE("SSL_read()", ret);

    if (ret < 0)
        return SSL_FATAL_ERROR;
    else
        return ret;
}


int CyaSSL_shutdown(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_shutdown()");

    if (ssl->options.quietShutdown) {
        CYASSL_MSG("quiet shutdown, no close notify sent"); 
        return 0;
    }

    /* try to send close notify, not an error if can't */
    if (!ssl->options.isClosed && !ssl->options.connReset &&
                                  !ssl->options.sentNotify) {
        ssl->error = SendAlert(ssl, alert_warning, close_notify);
        if (ssl->error < 0) {
            CYASSL_ERROR(ssl->error);
            return SSL_FATAL_ERROR;
        }
        ssl->options.sentNotify = 1;  /* don't send close_notify twice */
    }

    CYASSL_LEAVE("SSL_shutdown()", ssl->error);

    ssl->error = SSL_ERROR_SYSCALL;   /* simulate OpenSSL behavior */

    return 0;
}


int CyaSSL_get_error(CYASSL* ssl, int ret)
{
    CYASSL_ENTER("SSL_get_error");
    CYASSL_LEAVE("SSL_get_error", ssl->error);
    if (ret > 0)
        return SSL_ERROR_NONE;

    if (ssl->error == WANT_READ)
        return SSL_ERROR_WANT_READ;         /* convert to OpenSSL type */
    else if (ssl->error == WANT_WRITE)
        return SSL_ERROR_WANT_WRITE;        /* convert to OpenSSL type */
    else if (ssl->error == ZERO_RETURN) 
        return SSL_ERROR_ZERO_RETURN;       /* convert to OpenSSL type */
    return ssl->error;
}


int CyaSSL_want_read(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_want_read");
    if (ssl->error == WANT_READ)
        return 1;

    return 0;
}


int CyaSSL_want_write(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_want_write");
    if (ssl->error == WANT_WRITE)
        return 1;

    return 0;
}


char* CyaSSL_ERR_error_string(unsigned long errNumber, char* data)
{
    static const char* msg = "Please supply a buffer for error string";

    CYASSL_ENTER("ERR_error_string");
    if (data) {
        SetErrorString(errNumber, data);
        return data;
    }

    return (char*)msg;
}


void CyaSSL_ERR_error_string_n(unsigned long e, char* buf, unsigned long len)
{
    CYASSL_ENTER("CyaSSL_ERR_error_string_n");
    if (len) CyaSSL_ERR_error_string(e, buf);
}


#ifndef NO_FILESYSTEM

void CyaSSL_ERR_print_errors_fp(FILE* fp, int err)
{
    char data[MAX_ERROR_SZ + 1];

    CYASSL_ENTER("CyaSSL_ERR_print_errors_fp");
    SetErrorString(err, data);
    fprintf(fp, "%s", data);
}

#endif


int CyaSSL_pending(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_pending");
    return ssl->buffers.clearOutputBuffer.length;
}


static CyaSSL_Mutex ca_mutex;   /* CA signers mutex */

/* does CA already exist on signer list */
int AlreadySigner(CYASSL_CTX* ctx, byte* hash)
{
    Signer* signers;
    int     ret = 0;

    if (LockMutex(&ca_mutex) != 0)
        return  ret;
    signers = ctx->caList;
    while (signers) {
        if (XMEMCMP(hash, signers->hash, SHA_DIGEST_SIZE) == 0) {
            ret = 1;
            break;
        }
        signers = signers->next;
    }
    UnLockMutex(&ca_mutex);

    return ret;
}


/* return CA if found, otherwise NULL */
Signer* GetCA(Signer* signers, byte* hash)
{
    Signer* ret = 0;

    if (LockMutex(&ca_mutex) != 0)
        return ret;
    while (signers) {
        if (XMEMCMP(hash, signers->hash, SHA_DIGEST_SIZE) == 0) {
            ret = signers;
            break;
        }
        signers = signers->next;
    }
    UnLockMutex(&ca_mutex);

    return ret;
}


/* owns der, internal now uses too */
/* force flag means override CA check, ok for root certs that user requested
   if they're from a chain we don't want to force, ever */
int AddCA(CYASSL_CTX* ctx, buffer der, int force)
{
    int         ret;
    DecodedCert cert;
    Signer*     signer = 0;

    CYASSL_MSG("Adding a CA");
    InitDecodedCert(&cert, der.buffer, der.length, ctx->heap);
    ret = ParseCert(&cert, CA_TYPE, ctx->verifyPeer, 0);
    CYASSL_MSG("    Parsed new CA");

    if (ret == 0 && cert.isCA == 0 && !force) {
        CYASSL_MSG("    Can't add as CA if not actually one");
        ret = NOT_CA_ERROR;
    }
    else if (ret == 0 && AlreadySigner(ctx, cert.subjectHash)) {
        CYASSL_MSG("    Already have this CA, not adding again");
        (void)ret;
    } 
    else if (ret == 0) {
        /* take over signer parts */
        signer = MakeSigner(ctx->heap);
        if (!signer)
            ret = MEMORY_ERROR;
        else {
            signer->keyOID     = cert.keyOID;
            signer->publicKey  = cert.publicKey;
            signer->pubKeySize = cert.pubKeySize;
            signer->name = cert.subjectCN;
            XMEMCPY(signer->hash, cert.subjectHash, SHA_DIGEST_SIZE);

            cert.publicKey = 0;  /* don't free here */
            cert.subjectCN = 0;

            if (LockMutex(&ca_mutex) == 0) {
                signer->next = ctx->caList;
                ctx->caList  = signer;   /* takes ownership */
                UnLockMutex(&ca_mutex);
            }
            else {
                CYASSL_MSG("    CA Mutex Lock failed");
                ret = BAD_MUTEX_ERROR;
                FreeSigners(signer, ctx->heap);
            }
        }
    }

    CYASSL_MSG("    Freeing Parsed CA");
    FreeDecodedCert(&cert);
    CYASSL_MSG("    Freeing der CA");
    XFREE(der.buffer, ctx->heap, DYNAMIC_TYPE_CA);
    CYASSL_MSG("        OK Freeing der CA");

    CYASSL_LEAVE("AddCA", ret);
    if (ret == 0) return SSL_SUCCESS;
    return ret;
}


#ifndef NO_SESSION_CACHE

    /* basic config gives a cache with 33 sessions, adequate for clients and
       embedded servers

       BIG_SESSION_CACHE allows 1055 sessions, adequate for servers that aren't
       under heavy load, basically allows 200 new sessions per minute

       HUGE_SESSION_CACHE yields 65,791 sessions, for servers under heavy load,
       allows over 13,000 new sessions per minute or over 200 new sessions per
       second

       SMALL_SESSION_CACHE only stores 6 sessions, good for embedded clients
       or systems where the default of nearly 3kB is too much RAM, this define
       uses less than 500 bytes RAM
    */
    #ifdef HUGE_SESSION_CACHE
        #define SESSIONS_PER_ROW 11
        #define SESSION_ROWS 5981
    #elif defined(BIG_SESSION_CACHE)
        #define SESSIONS_PER_ROW 5
        #define SESSION_ROWS 211
    #elif defined(SMALL_SESSION_CACHE)
        #define SESSIONS_PER_ROW 2
        #define SESSION_ROWS 3 
    #else
        #define SESSIONS_PER_ROW 3
        #define SESSION_ROWS 11
    #endif

    typedef struct SessionRow {
        int nextIdx;                           /* where to place next one   */
        int totalCount;                        /* sessions ever on this row */
        CYASSL_SESSION Sessions[SESSIONS_PER_ROW];
    } SessionRow;

    static SessionRow SessionCache[SESSION_ROWS];

    static CyaSSL_Mutex session_mutex;   /* SessionCache mutex */

#endif /* NO_SESSION_CACHE */


    /* Remove PEM header/footer, convert to ASN1, store any encrypted data 
       info->consumed tracks of PEM bytes consumed in case multiple parts */
    static int PemToDer(const unsigned char* buff, long sz, int type,
                      buffer* der, void* heap, EncryptedInfo* info, int* eccKey)
    {
        char  header[PEM_LINE_LEN];
        char  footer[PEM_LINE_LEN];
        char* headerEnd;
        char* footerEnd;
        char* consumedEnd;
        long  neededSz;
        int   pkcs8    = 0;
        int   pkcs8Enc = 0;
        int   dynamicType = 0;

        (void)heap;
        (void)dynamicType;
        (void)pkcs8Enc;

        if (type == CERT_TYPE || type == CA_TYPE)  {
            XSTRNCPY(header, "-----BEGIN CERTIFICATE-----", sizeof(header));
            XSTRNCPY(footer, "-----END CERTIFICATE-----", sizeof(footer));
            dynamicType = (type == CA_TYPE) ? DYNAMIC_TYPE_CA :
                                              DYNAMIC_TYPE_CERT;
        } else if (type == DH_PARAM_TYPE) {
            XSTRNCPY(header, "-----BEGIN DH PARAMETERS-----", sizeof(header));
            XSTRNCPY(footer, "-----END DH PARAMETERS-----", sizeof(footer));
            dynamicType = DYNAMIC_TYPE_KEY;
        } else {
            XSTRNCPY(header, "-----BEGIN RSA PRIVATE KEY-----", sizeof(header));
            XSTRNCPY(footer, "-----END RSA PRIVATE KEY-----", sizeof(footer));
            dynamicType = DYNAMIC_TYPE_KEY;
        }

        /* find header */
        headerEnd = XSTRSTR((char*)buff, header);
        if (!headerEnd && type == PRIVATEKEY_TYPE) {  /* may be pkcs8 */
            XSTRNCPY(header, "-----BEGIN PRIVATE KEY-----", sizeof(header));
            XSTRNCPY(footer, "-----END PRIVATE KEY-----", sizeof(footer));
        
            headerEnd = XSTRSTR((char*)buff, header);
            if (headerEnd)
                pkcs8 = 1;
            else {
                XSTRNCPY(header, "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                        sizeof(header));
                XSTRNCPY(footer, "-----END ENCRYPTED PRIVATE KEY-----",
                        sizeof(footer));

                headerEnd = XSTRSTR((char*)buff, header);
                if (headerEnd)
                    pkcs8Enc = 1;
            }
        }
        if (!headerEnd && type == PRIVATEKEY_TYPE) {  /* may be ecc */
            XSTRNCPY(header, "-----BEGIN EC PRIVATE KEY-----", sizeof(header));
            XSTRNCPY(footer, "-----END EC PRIVATE KEY-----", sizeof(footer));
        
            headerEnd = XSTRSTR((char*)buff, header);
            if (headerEnd)
                *eccKey = 1;
        }
        if (!headerEnd)
            return SSL_BAD_FILE;
        headerEnd += XSTRLEN(header);

        /* get next line */
        if (headerEnd[0] == '\n')
            headerEnd++;
        else if (headerEnd[1] == '\n')
            headerEnd += 2;
        else
            return SSL_BAD_FILE;

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
    {
        /* remove encrypted header if there */
        char encHeader[] = "Proc-Type";
        char* line = XSTRSTR((char*)buff, encHeader);
        if (line) {
            char* newline;
            char* finish;
            char* start  = XSTRSTR(line, "DES");
    
            if (!start)
                start = XSTRSTR(line, "AES");
            
            if (!start) return SSL_BAD_FILE;
            if (!info)  return SSL_BAD_FILE;
            
            finish = XSTRSTR(start, ",");

            if (start && finish && (start < finish)) {
                newline = XSTRSTR(finish, "\r");

                XMEMCPY(info->name, start, finish - start);
                info->name[finish - start] = 0;
                XMEMCPY(info->iv, finish + 1, sizeof(info->iv));

                if (!newline) newline = XSTRSTR(finish, "\n");
                if (newline && (newline > finish)) {
                    info->ivSz = (word32)(newline - (finish + 1));
                    info->set = 1;
                }
                else
                    return SSL_BAD_FILE;
            }
            else
                return SSL_BAD_FILE;

            /* eat blank line */
            while (*newline == '\r' || *newline == '\n')
                newline++;
            headerEnd = newline;
        }
    }
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

        /* find footer */
        footerEnd = XSTRSTR((char*)buff, footer);
        if (!footerEnd) return SSL_BAD_FILE;

        consumedEnd = footerEnd + XSTRLEN(footer);

        /* get next line */
        if (consumedEnd[0] == '\n')
            consumedEnd++;
        else if (consumedEnd[1] == '\n')
            consumedEnd += 2;
        else
            return SSL_BAD_FILE;

        if (info)
            info->consumed = (long)(consumedEnd - (char*)buff);

        /* set up der buffer */
        neededSz = (long)(footerEnd - headerEnd);
        if (neededSz > sz || neededSz < 0) return SSL_BAD_FILE;
        der->buffer = (byte*) XMALLOC(neededSz, heap, dynamicType);
        if (!der->buffer) return MEMORY_ERROR;
        der->length = neededSz;

        if (Base64_Decode((byte*)headerEnd, neededSz, der->buffer,
                          &der->length) < 0)
            return SSL_BAD_FILE;

        if (pkcs8)
            return ToTraditional(der->buffer, der->length);

#ifdef OPENSSL_EXTRA
         if (pkcs8Enc) {
            int  passwordSz;
            char password[80];

            if (!info->ctx->passwd_cb)
                return SSL_BAD_FILE;  /* no callback error */
            passwordSz = info->ctx->passwd_cb(password, sizeof(password), 0,
                                              info->ctx->userdata);
            return ToTraditionalEnc(der->buffer, der->length, password,
                                    passwordSz);
         }
#endif

        return 0;
    }


    /* process the buffer buff, legnth sz, into ctx of format and type
       used tracks bytes consumed, userChain specifies a user cert chain
       to pass during the handshake */
    static int ProcessBuffer(CYASSL_CTX* ctx, const unsigned char* buff,
                             long sz, int format, int type, CYASSL* ssl,
                             long* used, int userChain)
    {
        EncryptedInfo info;
        buffer        der;        /* holds DER or RAW (for NTRU) */
        int           dynamicType = 0;
        int           eccKey = 0;

        info.set      = 0;
        info.ctx      = ctx;
        info.consumed = 0;
        der.buffer    = 0;

        (void)dynamicType;

        if (used)
            *used = sz;     /* used bytes default to sz, PEM chain may shorten*/

        if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM 
                                        && format != SSL_FILETYPE_RAW)
            return SSL_BAD_FILETYPE;

        if (type == CA_TYPE)
            dynamicType = DYNAMIC_TYPE_CA;
        else if (type == CERT_TYPE)
            dynamicType = DYNAMIC_TYPE_CERT;
        else
            dynamicType = DYNAMIC_TYPE_KEY;

        if (format == SSL_FILETYPE_PEM) {
            int ret = PemToDer(buff, sz, type, &der, ctx->heap, &info, &eccKey);
            if (ret < 0) {
                XFREE(der.buffer, ctx->heap, dynamicType);
                return ret;
            }
            if (used)
                *used = info.consumed;
            /* we may have a user cert chain, try to consume */
            if (userChain && type == CERT_TYPE && info.consumed < sz) {
                byte   staticBuffer[FILE_BUFFER_SIZE];  /* tmp chain buffer */
                byte*  chainBuffer = staticBuffer;
                int    dynamicBuffer = 0;
                word32 bufferSz = sizeof(staticBuffer);
                long   consumed = info.consumed;
                word32 idx = 0;

                if ( (sz - consumed) > (int)bufferSz) {
                    CYASSL_MSG("Growing Tmp Chain Buffer");
                    bufferSz = sz - consumed;  /* will shrink to actual size */
                    chainBuffer = (byte*)XMALLOC(bufferSz, ctx->heap,
                                                 DYNAMIC_FILE_TYPE);
                    if (chainBuffer == NULL) {
                        XFREE(der.buffer, ctx->heap, dynamicType);
                        return MEMORY_E;
                    }
                    dynamicBuffer = 1;
                }

                CYASSL_MSG("Processing Cert Chain");
                while (consumed < sz) {
                    long   left;
                    buffer part;
                    info.consumed = 0;
                    part.buffer = 0;

                    ret = PemToDer(buff + consumed, sz - consumed, type, &part,
                                   ctx->heap, &info, &eccKey);
                    if (ret == 0) {
                        if ( (idx + part.length) > bufferSz) {
                            CYASSL_MSG("   Cert Chain bigger than buffer");
                            ret = BUFFER_E;
                        }
                        else {
                            c32to24(part.length, &chainBuffer[idx]);
                            idx += CERT_HEADER_SZ;
                            XMEMCPY(&chainBuffer[idx], part.buffer,part.length);
                            idx += part.length;
                            consumed  += info.consumed;
                            if (used)
                                *used += info.consumed;
                        }
                    }

                    XFREE(part.buffer, ctx->heap, dynamicType);
                    if (ret < 0) {
                        CYASSL_MSG("   Error in Cert in Chain");
                        XFREE(der.buffer, ctx->heap, dynamicType);
                        return ret;
                    }
                    CYASSL_MSG("   Consumed another Cert in Chain");

                    left = sz - consumed;
                    if (left > 0 && left < CERT_MIN_SIZE) {
                        CYASSL_MSG("   Non Cert at end of file");
                        break;
                    }
                }
                CYASSL_MSG("Finished Processing Cert Chain");
                ctx->certChain.buffer = (byte*)XMALLOC(idx, ctx->heap,
                                                       dynamicType);
                if (ctx->certChain.buffer) {
                    ctx->certChain.length = idx;
                    XMEMCPY(ctx->certChain.buffer, chainBuffer, idx);
                }
                if (dynamicBuffer)
                    XFREE(chainBuffer, ctx->heap, DYNAMIC_FILE_TYPE);
                if (ctx->certChain.buffer == NULL) {
                    XFREE(der.buffer, ctx->heap, dynamicType);
                    return MEMORY_E;
                }
            }
        }
        else {  /* ASN1 (DER) or RAW (NTRU) */
            der.buffer = (byte*) XMALLOC(sz, ctx->heap, dynamicType);
            if (!der.buffer) return MEMORY_ERROR;
            XMEMCPY(der.buffer, buff, sz);
            der.length = sz;
        }

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
        if (info.set) {
            /* decrypt */
            char password[80];
            int  passwordSz;
            int  ret;

            byte key[AES_256_KEY_SIZE];
            byte  iv[AES_IV_SIZE];

            if (!ctx->passwd_cb) {
                XFREE(der.buffer, ctx->heap, dynamicType);
                return NO_PASSWORD;
            }

            /* use file's salt for key derivation, hex decode first */
            if (Base16_Decode(info.iv, info.ivSz, info.iv, &info.ivSz) != 0) {
                XFREE(der.buffer, ctx->heap, dynamicType);
                return ASN_INPUT_E;
            }

            passwordSz = ctx->passwd_cb(password, sizeof(password), 0,
                                    ctx->userdata);
            if ( (ret = EVP_BytesToKey(info.name, "MD5", info.iv,
                            (byte*)password, passwordSz, 1, key, iv)) <= 0) {
                XFREE(der.buffer, ctx->heap, dynamicType);
                return ret;
            }

            if (XSTRNCMP(info.name, "DES-CBC", 7) == 0) {
                Des enc;
                Des_SetKey(&enc, key, info.iv, DES_DECRYPTION);
                Des_CbcDecrypt(&enc, der.buffer, der.buffer, der.length);
            }
            else if (XSTRNCMP(info.name, "DES-EDE3-CBC", 13) == 0) {
                Des3 enc;
                Des3_SetKey(&enc, key, info.iv, DES_DECRYPTION);
                Des3_CbcDecrypt(&enc, der.buffer, der.buffer, der.length);
            }
            else if (XSTRNCMP(info.name, "AES-128-CBC", 13) == 0) {
                Aes enc;
                AesSetKey(&enc, key, AES_128_KEY_SIZE, info.iv, AES_DECRYPTION);
                AesCbcDecrypt(&enc, der.buffer, der.buffer, der.length);
            }
            else if (XSTRNCMP(info.name, "AES-192-CBC", 13) == 0) {
                Aes enc;
                AesSetKey(&enc, key, AES_192_KEY_SIZE, info.iv, AES_DECRYPTION);
                AesCbcDecrypt(&enc, der.buffer, der.buffer, der.length);
            }
            else if (XSTRNCMP(info.name, "AES-256-CBC", 13) == 0) {
                Aes enc;
                AesSetKey(&enc, key, AES_256_KEY_SIZE, info.iv, AES_DECRYPTION);
                AesCbcDecrypt(&enc, der.buffer, der.buffer, der.length);
            }
            else { 
                XFREE(der.buffer, ctx->heap, dynamicType);
                return SSL_BAD_FILE;
            }
        }
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

        if (type == CA_TYPE)
            return AddCA(ctx, der, 1);  /* takes der over, force user request */
        else if (type == CERT_TYPE) {
            if (ssl) {
                if (ssl->buffers.weOwnCert && ssl->buffers.certificate.buffer)
                    XFREE(ssl->buffers.certificate.buffer, ctx->heap,
                          dynamicType);
                ssl->buffers.certificate = der;
                ssl->buffers.weOwnCert = 1;
            }
            else {
                if (ctx->certificate.buffer)
                    XFREE(ctx->certificate.buffer, ctx->heap, dynamicType);
                ctx->certificate = der;     /* takes der over */
            }
        }
        else if (type == PRIVATEKEY_TYPE) {
            if (ssl) {
                if (ssl->buffers.weOwnKey && ssl->buffers.key.buffer)
                    XFREE(ssl->buffers.key.buffer, ctx->heap, dynamicType);
                ssl->buffers.key = der;
                ssl->buffers.weOwnKey = 1;
            }
            else {
                if (ctx->privateKey.buffer)
                    XFREE(ctx->privateKey.buffer, ctx->heap, dynamicType);
                ctx->privateKey = der;      /* takes der over */
            }
        }
        else {
            XFREE(der.buffer, ctx->heap, dynamicType);
            return SSL_BAD_CERTTYPE;
        }

        if (type == PRIVATEKEY_TYPE && format != SSL_FILETYPE_RAW) {
            if (!eccKey) { 
                /* make sure RSA key can be used */
                RsaKey key;
                word32 idx = 0;
        
                InitRsaKey(&key, 0);
                if (RsaPrivateKeyDecode(der.buffer,&idx,&key,der.length) != 0) {
#ifdef HAVE_ECC  
                    /* could have DER ECC (or pkcs8 ecc), no easy way to tell */
                    eccKey = 1;  /* so try it out */
#endif
                    if (!eccKey) {
                        FreeRsaKey(&key);
                        return SSL_BAD_FILE;
                    }
                }
                FreeRsaKey(&key);
            }
#ifdef HAVE_ECC  
            if (eccKey ) {
                /* make sure ECC key can be used */
                word32  idx = 0;
                ecc_key key;

                ecc_init(&key);
                if (EccPrivateKeyDecode(der.buffer,&idx,&key,der.length) != 0) {
                    ecc_free(&key);
                    return SSL_BAD_FILE;
                }
                ecc_free(&key);
                ctx->haveECDSA = 1;
            }
#endif /* HAVE_ECC */
        }

        return SSL_SUCCESS;
    }


/* CA PEM file for verification, may have multiple/chain certs to process */
static int ProcessChainBuffer(CYASSL_CTX* ctx, const unsigned char* buff,
                            long sz, int format, int type, CYASSL* ssl)
{
    long used = 0;
    int  ret  = 0;

    CYASSL_MSG("Processing CA PEM file");
    while (used < sz) {
        long consumed = 0;
        long left;

        ret = ProcessBuffer(ctx, buff + used, sz - used, format, type, ssl,
                            &consumed, 0);
        if (ret < 0)
            break;

        CYASSL_MSG("   Processed a CA");
        used += consumed;

        left = sz - used;
        if (left > 0 && left < CERT_MIN_SIZE) { /* non cert stuff at eof */
            CYASSL_MSG("   Non CA cert at eof");
            break;
        }
    }
    return ret;
}


#ifndef NO_FILESYSTEM

#ifndef MICRIUM
    #define XFILE      FILE
    #define XFOPEN     fopen 
    #define XFSEEK     fseek
    #define XFTELL     ftell
    #define XREWIND    rewind
    #define XFREAD     fread
    #define XFCLOSE    fclose
    #define XSEEK_END  SEEK_END
#else
    #include <fs.h>
    #define XFILE      FS_FILE
    #define XFOPEN     fs_fopen 
    #define XFSEEK     fs_fseek
    #define XFTELL     fs_ftell
    #define XREWIND    fs_rewind
    #define XFREAD     fs_fread
    #define XFCLOSE    fs_fclose
    #define XSEEK_END  FS_SEEK_END
#endif


/* process a file with name fname into ctx of format and type
   userChain specifies a user certificate chain to pass during handshake */
static int ProcessFile(CYASSL_CTX* ctx, const char* fname, int format, int type,
                       CYASSL* ssl, int userChain)
{
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    int    ret;
    long   sz = 0;
    XFILE* file = XFOPEN(fname, "rb"); 

    if (!file) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > (long)sizeof(staticBuffer)) {
        CYASSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, ctx->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ( (ret = XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else {
        if (type == CA_TYPE && format == SSL_FILETYPE_PEM) 
            ret = ProcessChainBuffer(ctx, myBuffer, sz, format, type, ssl);
        else
            ret = ProcessBuffer(ctx, myBuffer, sz, format, type, ssl, NULL,
                                userChain);
    }

    XFCLOSE(file);
    if (dynamic) XFREE(myBuffer, ctx->heap, DYNAMIC_TYPE_FILE);

    return ret;
}


/* just one for now TODO: add dir support from path */
int CyaSSL_CTX_load_verify_locations(CYASSL_CTX* ctx, const char* file,
                                     const char* path)
{
    CYASSL_ENTER("SSL_CTX_load_verify_locations");
    (void)path;

    if (ctx == NULL || file == NULL)
        return SSL_FAILURE;

    return ProcessFile(ctx, file, SSL_FILETYPE_PEM, CA_TYPE, NULL, 0);
}


#ifdef CYASSL_DER_LOAD

/* Add format parameter to allow DER load of CA files */
int CyaSSL_CTX_der_load_verify_locations(CYASSL_CTX* ctx, const char* file,
                                         int format)
{
    CYASSL_ENTER("CyaSSL_CTX_der_load_verify_locations");
    if (ctx == NULL || file == NULL)
        return SSL_FAILURE;

    if (ProcessFile(ctx, file, format, CA_TYPE, NULL, 0) == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}

#endif /* CYASSL_DER_LOAD */


#ifdef CYASSL_CERT_GEN

/* load pem cert from file into der buffer, return der size or error */
int CyaSSL_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz) 
{
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  fileBuf = staticBuffer;
    int    dynamic = 0;
    int    ret;
    int    ecc = 0;
    long   sz = 0;
    XFILE* file = XFOPEN(fileName, "rb"); 
    EncryptedInfo info;
    buffer        converted;

    CYASSL_ENTER("CyaSSL_PemCertToDer");
    converted.buffer = 0;

    if (!file) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > (long)sizeof(staticBuffer)) {
        fileBuf = (byte*) XMALLOC(sz, 0, DYNAMIC_TYPE_FILE);
        if (fileBuf == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ( (ret = XFREAD(fileBuf, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else
        ret = PemToDer(fileBuf, sz, CA_TYPE, &converted, 0, &info, &ecc);

    if (ret == 0) {
        if (converted.length < (word32)derSz) {
            XMEMCPY(derBuf, converted.buffer, converted.length);
            ret = converted.length;
        }
        else
            ret = BUFFER_E;
    }       

    XFREE(converted.buffer, 0, DYNAMIC_TYPE_CA); 
    if (dynamic)
        XFREE(fileBuf, 0, DYNAMIC_TYPE_FILE); 
    XFCLOSE(file);

    return ret;
}

#endif /* CYASSL_CERT_GEN */


int CyaSSL_CTX_use_certificate_file(CYASSL_CTX* ctx, const char* file,
                                    int format)
{
    CYASSL_ENTER("CyaSSL_CTX_use_certificate_file");
    if (ProcessFile(ctx, file, format, CERT_TYPE, NULL, 0) == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_CTX_use_PrivateKey_file(CYASSL_CTX* ctx, const char* file,int format)
{
    CYASSL_ENTER("CyaSSL_CTX_use_PrivateKey_file");
    if (ProcessFile(ctx, file, format, PRIVATEKEY_TYPE, NULL, 0) == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_CTX_use_certificate_chain_file(CYASSL_CTX* ctx, const char* file)
{
   /* procces up to MAX_CHAIN_DEPTH plus subject cert */
   CYASSL_ENTER("CyaSSL_CTX_use_certificate_chain_file");
   if (ProcessFile(ctx, file, SSL_FILETYPE_PEM,CERT_TYPE,NULL,1) == SSL_SUCCESS)
       return SSL_SUCCESS;

   return SSL_FAILURE;
}


#ifdef OPENSSL_EXTRA
/* put SSL type in extra for now, not very common */

int CyaSSL_use_certificate_file(CYASSL* ssl, const char* file, int format)
{
    CYASSL_ENTER("CyaSSL_use_certificate_file");
    if (ProcessFile(ssl->ctx, file, format, CERT_TYPE, ssl, 0) == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_use_PrivateKey_file(CYASSL* ssl, const char* file, int format)
{
    CYASSL_ENTER("CyaSSL_use_PrivateKey_file");
    if (ProcessFile(ssl->ctx, file, format, PRIVATEKEY_TYPE, ssl, 0)
                                                                 == SSL_SUCCESS)
        return SSL_SUCCESS;

    return SSL_FAILURE;
}


int CyaSSL_use_certificate_chain_file(CYASSL* ssl, const char* file)
{
   /* procces up to MAX_CHAIN_DEPTH plus subject cert */
   CYASSL_ENTER("CyaSSL_use_certificate_chain_file");
   if (ProcessFile(ssl->ctx, file, SSL_FILETYPE_PEM, CERT_TYPE, ssl, 1)
                                                                 == SSL_SUCCESS)
       return SSL_SUCCESS;

   return SSL_FAILURE;
}


/* server wrapper for ctx or ssl Diffie-Hellman parameters */
static int CyaSSL_SetTmpDH_buffer_wrapper(CYASSL_CTX* ctx, CYASSL* ssl,
                                  const unsigned char* buf, long sz, int format)
{
    buffer der;
    int    ret;
    int    weOwnDer = 0;
    byte   p[MAX_DH_SIZE];
    byte   g[MAX_DH_SIZE];
    word32 pSz = sizeof(p);
    word32 gSz = sizeof(g);

    der.buffer = (byte*)buf;
    der.length = sz;

    if (format != SSL_FILETYPE_ASN1 && format != SSL_FILETYPE_PEM)
        return SSL_BAD_FILETYPE;

    if (format == SSL_FILETYPE_PEM) {
        der.buffer = NULL;
        ret = PemToDer(buf, sz, DH_PARAM_TYPE, &der, ctx->heap, NULL,NULL);
        if (ret < 0) {
            XFREE(der.buffer, ctx->heap, DYNAMIC_TYPE_KEY);
            return ret;
        }
        weOwnDer = 1;
    }

    if (DhParamsLoad(der.buffer, der.length, p, &pSz, g, &gSz) < 0)
        ret = SSL_BAD_FILETYPE;
    else {
        if (ssl)
            ret = CyaSSL_SetTmpDH(ssl, p, pSz, g, gSz);
        else
            ret = CyaSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);
    }

    if (weOwnDer)
        XFREE(der.buffer, ctx->heap, DYNAMIC_TYPE_KEY);

    return ret;
}

/* server Diffie-Hellman parameters */
int CyaSSL_SetTmpDH_buffer(CYASSL* ssl, const unsigned char* buf, long sz,
                           int format)
{
    return CyaSSL_SetTmpDH_buffer_wrapper(ssl->ctx, ssl, buf, sz, format);
}


/* server ctx Diffie-Hellman parameters */
int CyaSSL_CTX_SetTmpDH_buffer(CYASSL_CTX* ctx, const unsigned char* buf,
                               long sz, int format)
{
    return CyaSSL_SetTmpDH_buffer_wrapper(ctx, NULL, buf, sz, format);
}


#if !defined(NO_FILESYSTEM)

/* server Diffie-Hellman parameters */
static int CyaSSL_SetTmpDH_file_wrapper(CYASSL_CTX* ctx, CYASSL* ssl,
                                        const char* fname, int format)
{
    byte   staticBuffer[FILE_BUFFER_SIZE];
    byte*  myBuffer = staticBuffer;
    int    dynamic = 0;
    int    ret;
    long   sz = 0;
    XFILE* file = XFOPEN(fname, "rb"); 

    if (!file) return SSL_BAD_FILE;
    XFSEEK(file, 0, XSEEK_END);
    sz = XFTELL(file);
    XREWIND(file);

    if (sz > (long)sizeof(staticBuffer)) {
        CYASSL_MSG("Getting dynamic buffer");
        myBuffer = (byte*) XMALLOC(sz, ctx->heap, DYNAMIC_TYPE_FILE);
        if (myBuffer == NULL) {
            XFCLOSE(file);
            return SSL_BAD_FILE;
        }
        dynamic = 1;
    }

    if ( (ret = XFREAD(myBuffer, sz, 1, file)) < 0)
        ret = SSL_BAD_FILE;
    else {
        if (ssl)
            ret = CyaSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
        else
            ret = CyaSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }

    XFCLOSE(file);
    if (dynamic) XFREE(myBuffer, ctx->heap, DYNAMIC_TYPE_FILE);

    return ret;
}

/* server Diffie-Hellman parameters */
int CyaSSL_SetTmpDH_file(CYASSL* ssl, const char* fname, int format)
{
    return CyaSSL_SetTmpDH_file_wrapper(ssl->ctx, ssl, fname, format);
}


/* server Diffie-Hellman parameters */
int CyaSSL_CTX_SetTmpDH_file(CYASSL_CTX* ctx, const char* fname, int format)
{
    return CyaSSL_SetTmpDH_file_wrapper(ctx, NULL, fname, format);
}


#endif /* !NO_FILESYSTEM */
#endif /* OPENSSL_EXTRA */

#ifdef HAVE_NTRU

int CyaSSL_CTX_use_NTRUPrivateKey_file(CYASSL_CTX* ctx, const char* file)
{
    CYASSL_ENTER("CyaSSL_CTX_use_NTRUPrivateKey_file");
    if (ProcessFile(ctx, file, SSL_FILETYPE_RAW, PRIVATEKEY_TYPE, NULL, 0)
                         == SSL_SUCCESS) {
        ctx->haveNTRU = 1;
        return SSL_SUCCESS;
    }

    return SSL_FAILURE;
}

#endif /* HAVE_NTRU */



#ifdef OPENSSL_EXTRA

    int CyaSSL_CTX_use_RSAPrivateKey_file(CYASSL_CTX* ctx,const char* file,
                                       int format)
    {
        CYASSL_ENTER("SSL_CTX_use_RSAPrivateKey_file");
        if (ProcessFile(ctx, file,format,PRIVATEKEY_TYPE,NULL,0) == SSL_SUCCESS)
            return SSL_SUCCESS;

        return SSL_FAILURE;
    }

    int CyaSSL_use_RSAPrivateKey_file(CYASSL* ssl, const char* file, int format)
    {
        CYASSL_ENTER("CyaSSL_use_RSAPrivateKey_file");
        if (ProcessFile(ssl->ctx, file, format, PRIVATEKEY_TYPE, ssl, 0)
                                                                 == SSL_SUCCESS)
            return SSL_SUCCESS;

        return SSL_FAILURE;
    }

#endif /* OPENSSL_EXTRA */

#endif /* NO_FILESYSTEM */


void CyaSSL_CTX_set_verify(CYASSL_CTX* ctx, int mode, VerifyCallback vc)
{
    CYASSL_ENTER("CyaSSL_CTX_set_verify");
    if (mode & SSL_VERIFY_PEER) {
        ctx->verifyPeer = 1;
        ctx->verifyNone = 0;  /* in case perviously set */
    }

    if (mode == SSL_VERIFY_NONE) {
        ctx->verifyNone = 1;
        ctx->verifyPeer = 0;  /* in case previously set */
    }

    if (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
        ctx->failNoCert = 1;

    ctx->verifyCallback = vc;
}


void CyaSSL_set_verify(CYASSL* ssl, int mode, VerifyCallback vc)
{
    CYASSL_ENTER("CyaSSL_set_verify");
    if (mode & SSL_VERIFY_PEER) {
        ssl->options.verifyPeer = 1;
        ssl->options.verifyNone = 0;  /* in case perviously set */
    }

    if (mode == SSL_VERIFY_NONE) {
        ssl->options.verifyNone = 1;
        ssl->options.verifyPeer = 0;  /* in case previously set */
    }

    if (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
        ssl->options.failNoCert = 1;

    ssl->verifyCallback = vc;
}


#ifndef NO_SESSION_CACHE

CYASSL_SESSION* CyaSSL_get_session(CYASSL* ssl)
{
    CYASSL_ENTER("SSL_get_session");
    return GetSession(ssl, 0);
}


int CyaSSL_set_session(CYASSL* ssl, CYASSL_SESSION* session)
{
    CYASSL_ENTER("SSL_set_session");
    if (session)
        return SetSession(ssl, session);

    return SSL_FAILURE;
}

#endif /* NO_SESSION_CACHE */


void CyaSSL_load_error_strings(void)   /* compatibility only */
{}


int CyaSSL_library_init(void)
{
    CYASSL_ENTER("SSL_library_init");
    if (CyaSSL_Init() == 0)
        return SSL_SUCCESS;
    else
        return SSL_FATAL_ERROR;
}


#ifndef NO_SESSION_CACHE

/* on by default if built in but allow user to turn off */
long CyaSSL_CTX_set_session_cache_mode(CYASSL_CTX* ctx, long mode)
{
    CYASSL_ENTER("SSL_CTX_set_session_cache_mode");
    if (mode == SSL_SESS_CACHE_OFF)
        ctx->sessionCacheOff = 1;

    if (mode == SSL_SESS_CACHE_NO_AUTO_CLEAR)
        ctx->sessionCacheFlushOff = 1;

    return SSL_SUCCESS;
}

#endif /* NO_SESSION_CACHE */


int CyaSSL_CTX_set_cipher_list(CYASSL_CTX* ctx, const char* list)
{
    CYASSL_ENTER("CyaSSL_CTX_set_cipher_list");
    if (SetCipherList(&ctx->suites, list))
        return SSL_SUCCESS;
    else
        return SSL_FAILURE;
}


int CyaSSL_set_cipher_list(CYASSL* ssl, const char* list)
{
    CYASSL_ENTER("CyaSSL_set_cipher_list");
    if (SetCipherList(&ssl->suites, list)) {
        byte havePSK = 0;

        #ifndef NO_PSK
            havePSK = ssl->options.havePSK;
        #endif

        InitSuites(&ssl->suites, ssl->version, ssl->options.haveDH, havePSK,
                   ssl->options.haveNTRU, ssl->options.haveECDSA,
                   ssl->ctx->method->side);

        return SSL_SUCCESS;
    }
    else
        return SSL_FAILURE;
}


/* client only parts */
#ifndef NO_CYASSL_CLIENT

    CYASSL_METHOD* CyaSSLv3_client_method(void)
    {
        CYASSL_METHOD* method =
                              (CYASSL_METHOD*) XMALLOC(sizeof(CYASSL_METHOD), 0,
                                                       DYNAMIC_TYPE_METHOD);
        CYASSL_ENTER("SSLv3_client_method");
        if (method)
            InitSSL_Method(method, MakeSSLv3());
        return method;
    }

    #ifdef CYASSL_DTLS
        CYASSL_METHOD* CyaDTLSv1_client_method(void)
        {
            CYASSL_METHOD* method =
                              (CYASSL_METHOD*) XMALLOC(sizeof(CYASSL_METHOD), 0,
                                                       DYNAMIC_TYPE_METHOD);
            CYASSL_ENTER("DTLSv1_client_method");
            if (method)
                InitSSL_Method(method, MakeDTLSv1());
            return method;
        }
    #endif


    /* please see note at top of README if you get an error from connect */
    int CyaSSL_connect(CYASSL* ssl)
    {
        int neededState;

        CYASSL_ENTER("SSL_connect()");

        #ifdef HAVE_ERRNO_H 
            errno = 0;
        #endif

        if (ssl->options.side != CLIENT_END) {
            CYASSL_ERROR(ssl->error = SIDE_ERROR);
            return SSL_FATAL_ERROR;
        }

        #ifdef CYASSL_DTLS
            if (ssl->version.major == DTLS_MAJOR && 
                                      ssl->version.minor == DTLS_MINOR) {
                ssl->options.dtls   = 1;
                ssl->options.tls    = 1;
                ssl->options.tls1_1 = 1;
            }
        #endif

        if (ssl->buffers.outputBuffer.length > 0) {
            if ( (ssl->error = SendBuffered(ssl)) == 0) {
                ssl->options.connectState++;
                CYASSL_MSG("connect state: Advanced from buffered send");
            }
            else {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
        }

        switch (ssl->options.connectState) {

        case CONNECT_BEGIN :
            /* always send client hello first */
            if ( (ssl->error = SendClientHello(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.connectState = CLIENT_HELLO_SENT;
            CYASSL_MSG("connect state: CLIENT_HELLO_SENT");

        case CLIENT_HELLO_SENT :
            neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                          SERVER_HELLODONE_COMPLETE;
            #ifdef CYASSL_DTLS
                if (ssl->options.dtls && !ssl->options.resuming)
                    neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
            #endif
            /* get response */
            while (ssl->options.serverState < neededState) {
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
                /* if resumption failed, reset needed state */
                else if (neededState == SERVER_FINISHED_COMPLETE)
                    if (!ssl->options.resuming) {
                        if (!ssl->options.dtls)
                            neededState = SERVER_HELLODONE_COMPLETE;
                        else
                            neededState = SERVER_HELLOVERIFYREQUEST_COMPLETE;
                    }
            }

            ssl->options.connectState = HELLO_AGAIN;
            CYASSL_MSG("connect state: HELLO_AGAIN");

        case HELLO_AGAIN :
            if (ssl->options.certOnly)
                return SSL_SUCCESS;

            #ifdef CYASSL_DTLS
                if (ssl->options.dtls && !ssl->options.resuming) {
                    /* re-init hashes, exclude first hello and verify request */
                    InitMd5(&ssl->hashMd5);
                    InitSha(&ssl->hashSha);
                    #ifndef NO_SHA256
                        if (IsAtLeastTLSv1_2(ssl))
                            InitSha256(&ssl->hashSha256);
                    #endif
                    if ( (ssl->error = SendClientHello(ssl)) != 0) {
                        CYASSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }
                }
            #endif

            ssl->options.connectState = HELLO_AGAIN_REPLY;
            CYASSL_MSG("connect state: HELLO_AGAIN_REPLY");

        case HELLO_AGAIN_REPLY :
            #ifdef CYASSL_DTLS
                if (ssl->options.dtls) {
                    neededState = ssl->options.resuming ?
                           SERVER_FINISHED_COMPLETE : SERVER_HELLODONE_COMPLETE;
            
                    /* get response */
                    while (ssl->options.serverState < neededState) {
                        if ( (ssl->error = ProcessReply(ssl)) < 0) {
                                CYASSL_ERROR(ssl->error);
                                return SSL_FATAL_ERROR;
                        }
                        /* if resumption failed, reset needed state */
                        else if (neededState == SERVER_FINISHED_COMPLETE)
                            if (!ssl->options.resuming)
                                neededState = SERVER_HELLODONE_COMPLETE;
                    }
                }
            #endif

            ssl->options.connectState = FIRST_REPLY_DONE;
            CYASSL_MSG("connect state: FIRST_REPLY_DONE");

        case FIRST_REPLY_DONE :
            if (ssl->options.sendVerify)
                if ( (ssl->error = SendCertificate(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }

            ssl->options.connectState = FIRST_REPLY_FIRST;
            CYASSL_MSG("connect state: FIRST_REPLY_FIRST");

        case FIRST_REPLY_FIRST :
            if (!ssl->options.resuming)
                if ( (ssl->error = SendClientKeyExchange(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }

            ssl->options.connectState = FIRST_REPLY_SECOND;
            CYASSL_MSG("connect state: FIRST_REPLY_SECOND");

        case FIRST_REPLY_SECOND :
            if (ssl->options.sendVerify)
                if ( (ssl->error = SendCertificateVerify(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
            }
            ssl->options.connectState = FIRST_REPLY_THIRD;
            CYASSL_MSG("connect state: FIRST_REPLY_THIRD");

        case FIRST_REPLY_THIRD :
            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.connectState = FIRST_REPLY_FOURTH;
            CYASSL_MSG("connect state: FIRST_REPLY_FOURTH");

        case FIRST_REPLY_FOURTH :
            if ( (ssl->error = SendFinished(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            ssl->options.connectState = FINISHED_DONE;
            CYASSL_MSG("connect state: FINISHED_DONE");

        case FINISHED_DONE :
            /* get response */
            while (ssl->options.serverState < SERVER_FINISHED_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
          
            ssl->options.connectState = SECOND_REPLY_DONE;
            CYASSL_MSG("connect state: SECOND_REPLY_DONE");

        case SECOND_REPLY_DONE:
            if (ssl->buffers.inputBuffer.dynamicFlag)
                ShrinkInputBuffer(ssl, NO_FORCED_FREE);
            CYASSL_LEAVE("SSL_connect()", SSL_SUCCESS);
            return SSL_SUCCESS;

        default:
            CYASSL_MSG("Unknown connect state ERROR");
            return SSL_FATAL_ERROR; /* unknown connect state */
        }
    }

#endif /* NO_CYASSL_CLIENT */


/* server only parts */
#ifndef NO_CYASSL_SERVER

    CYASSL_METHOD* CyaSSLv3_server_method(void)
    {
        CYASSL_METHOD* method =
                              (CYASSL_METHOD*) XMALLOC(sizeof(CYASSL_METHOD), 0,
                                                       DYNAMIC_TYPE_METHOD);
        CYASSL_ENTER("SSLv3_server_method");
        if (method) {
            InitSSL_Method(method, MakeSSLv3());
            method->side = SERVER_END;
        }
        return method;
    }


    #ifdef CYASSL_DTLS
        CYASSL_METHOD* CyaDTLSv1_server_method(void)
        {
            CYASSL_METHOD* method =
                              (CYASSL_METHOD*) XMALLOC(sizeof(CYASSL_METHOD), 0,
                                                       DYNAMIC_TYPE_METHOD);
            CYASSL_ENTER("DTLSv1_server_method");
            if (method) {
                InitSSL_Method(method, MakeDTLSv1());
                method->side = SERVER_END;
            }
            return method;
        }
    #endif


    int CyaSSL_accept(CYASSL* ssl)
    {
        byte havePSK = 0;
        CYASSL_ENTER("SSL_accept()");

        #ifdef HAVE_ERRNO_H 
            errno = 0;
        #endif

        #ifndef NO_PSK
            havePSK = ssl->options.havePSK;
        #endif

        if (ssl->options.side != SERVER_END) {
            CYASSL_ERROR(ssl->error = SIDE_ERROR);
            return SSL_FATAL_ERROR;
        }

        /* in case used set_accept_state after init */
        if (!havePSK && (ssl->buffers.certificate.buffer == NULL ||
                         ssl->buffers.key.buffer == NULL)) {
            CYASSL_MSG("accept error: don't have server cert and key");
            ssl->error = NO_PRIVATE_KEY;
            CYASSL_ERROR(ssl->error);
            return SSL_FATAL_ERROR;
        }

        #ifdef HAVE_ECC
            /* in case used set_accept_state after init */
            if (ssl->eccTempKeyPresent == 0) {
                if (ecc_make_key(&ssl->rng, ECDHE_SIZE, &ssl->eccTempKey) != 0){
                    ssl->error = ECC_MAKEKEY_ERROR;
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR; 
                } 
                ssl->eccTempKeyPresent = 1;
            }
        #endif

        #ifdef CYASSL_DTLS
            if (ssl->version.major == DTLS_MAJOR &&
                                      ssl->version.minor == DTLS_MINOR) {
                ssl->options.dtls   = 1;
                ssl->options.tls    = 1;
                ssl->options.tls1_1 = 1;
            }
        #endif

        if (ssl->buffers.outputBuffer.length > 0) {
            if ( (ssl->error = SendBuffered(ssl)) == 0) {
                ssl->options.acceptState++;
                CYASSL_MSG("accept state: Advanced from buffered send");
            }
            else {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
        }

        switch (ssl->options.acceptState) {
    
        case ACCEPT_BEGIN :
            /* get response */
            while (ssl->options.clientState < CLIENT_HELLO_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            ssl->options.acceptState = ACCEPT_CLIENT_HELLO_DONE;
            CYASSL_MSG("accept state ACCEPT_CLIENT_HELLO_DONE");

        case ACCEPT_CLIENT_HELLO_DONE :
            #ifdef CYASSL_DTLS
                if (ssl->options.dtls && !ssl->options.resuming)
                    if ( (ssl->error = SendHelloVerifyRequest(ssl)) != 0) {
                        CYASSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }
            #endif
            ssl->options.acceptState = HELLO_VERIFY_SENT;
            CYASSL_MSG("accept state HELLO_VERIFY_SENT");

        case HELLO_VERIFY_SENT:
            #ifdef CYASSL_DTLS
                if (ssl->options.dtls && !ssl->options.resuming) {
                    ssl->options.clientState = NULL_STATE;  /* get again */
                    /* re-init hashes, exclude first hello and verify request */
                    InitMd5(&ssl->hashMd5);
                    InitSha(&ssl->hashSha);
                    #ifndef NO_SHA256
                        if (IsAtLeastTLSv1_2(ssl))
                            InitSha256(&ssl->hashSha256);
                    #endif

                    while (ssl->options.clientState < CLIENT_HELLO_COMPLETE)
                        if ( (ssl->error = ProcessReply(ssl)) < 0) {
                            CYASSL_ERROR(ssl->error);
                            return SSL_FATAL_ERROR;
                        }
                }
            #endif
            ssl->options.acceptState = ACCEPT_FIRST_REPLY_DONE;
            CYASSL_MSG("accept state ACCEPT_FIRST_REPLY_DONE");

        case ACCEPT_FIRST_REPLY_DONE :
            if ( (ssl->error = SendServerHello(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.acceptState = SERVER_HELLO_SENT;
            CYASSL_MSG("accept state SERVER_HELLO_SENT");

        case SERVER_HELLO_SENT :
            if (!ssl->options.resuming) 
                if ( (ssl->error = SendCertificate(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            ssl->options.acceptState = CERT_SENT;
            CYASSL_MSG("accept state CERT_SENT");

        case CERT_SENT :
            if (!ssl->options.resuming) 
                if ( (ssl->error = SendServerKeyExchange(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            ssl->options.acceptState = KEY_EXCHANGE_SENT;
            CYASSL_MSG("accept state KEY_EXCHANGE_SENT");

        case KEY_EXCHANGE_SENT :
            if (!ssl->options.resuming) 
                if (ssl->options.verifyPeer)
                    if ( (ssl->error = SendCertificateRequest(ssl)) != 0) {
                        CYASSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }
            ssl->options.acceptState = CERT_REQ_SENT;
            CYASSL_MSG("accept state CERT_REQ_SENT");

        case CERT_REQ_SENT :
            if (!ssl->options.resuming) 
                if ( (ssl->error = SendServerHelloDone(ssl)) != 0) {
                    CYASSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            ssl->options.acceptState = SERVER_HELLO_DONE;
            CYASSL_MSG("accept state SERVER_HELLO_DONE");

        case SERVER_HELLO_DONE :
            if (!ssl->options.resuming) {
                while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
                    if ( (ssl->error = ProcessReply(ssl)) < 0) {
                        CYASSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }
            }
            ssl->options.acceptState = ACCEPT_SECOND_REPLY_DONE;
            CYASSL_MSG("accept state  ACCEPT_SECOND_REPLY_DONE");
          
        case ACCEPT_SECOND_REPLY_DONE : 
            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.acceptState = CHANGE_CIPHER_SENT;
            CYASSL_MSG("accept state  CHANGE_CIPHER_SENT");

        case CHANGE_CIPHER_SENT : 
            if ( (ssl->error = SendFinished(ssl)) != 0) {
                CYASSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            ssl->options.acceptState = ACCEPT_FINISHED_DONE;
            CYASSL_MSG("accept state ACCEPT_FINISHED_DONE");

        case ACCEPT_FINISHED_DONE :
            if (ssl->options.resuming)
                while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
                    if ( (ssl->error = ProcessReply(ssl)) < 0) {
                        CYASSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }

            ssl->options.acceptState = ACCEPT_THIRD_REPLY_DONE;
            CYASSL_MSG("accept state ACCEPT_THIRD_REPLY_DONE");

        case ACCEPT_THIRD_REPLY_DONE :
            if (ssl->buffers.inputBuffer.dynamicFlag)
                ShrinkInputBuffer(ssl, NO_FORCED_FREE);
            CYASSL_LEAVE("SSL_accept()", SSL_SUCCESS);
            return SSL_SUCCESS;

        default :
            CYASSL_MSG("Unknown accept state ERROR");
            return SSL_FATAL_ERROR;
        }
    }

#endif /* NO_CYASSL_SERVER */


int CyaSSL_Init(void)
{
    int ret = 0;
    CYASSL_ENTER("CyaSSL_Init");
#ifndef NO_SESSION_CACHE
    if (InitMutex(&session_mutex) != 0)
        ret = BAD_MUTEX_ERROR;
#endif
    if (InitMutex(&ca_mutex) != 0)
        ret = BAD_MUTEX_ERROR;

    return ret;
}


int CyaSSL_Cleanup(void)
{
    int ret = 0;
    CYASSL_ENTER("CyaSSL_Cleanup");
#ifndef NO_SESSION_CACHE
    if (FreeMutex(&session_mutex) != 0)
        ret = BAD_MUTEX_ERROR;
#endif
    if (FreeMutex(&ca_mutex) != 0)
        ret = BAD_MUTEX_ERROR;

    return ret;
}


#ifndef NO_SESSION_CACHE


static INLINE word32 HashSession(const byte* sessionID)
{
    /* id is random, just make 32 bit number from first 4 bytes for now */
    return (sessionID[0] << 24) | (sessionID[1] << 16) | (sessionID[2] <<  8) |
            sessionID[3];
}


void CyaSSL_flush_sessions(CYASSL_CTX* ctx, long tm)
{
    /* static table now, no flusing needed */
    (void)ctx;
    (void)tm;
}


CYASSL_SESSION* GetSession(CYASSL* ssl, byte* masterSecret)
{
    CYASSL_SESSION* ret = 0;
    const byte*  id = ssl->arrays.sessionID;
    word32       row;
    int          idx;
    
    if (ssl->options.sessionCacheOff)
        return 0;

    row = HashSession(id) % SESSION_ROWS;

    if (LockMutex(&session_mutex) != 0)
        return 0;
   
    if (SessionCache[row].totalCount >= SESSIONS_PER_ROW)
        idx = SESSIONS_PER_ROW - 1;
    else
        idx = SessionCache[row].nextIdx - 1;

    for (; idx >= 0; idx--) {
        CYASSL_SESSION* current;
        
        if (idx >= SESSIONS_PER_ROW)    /* server could have restarted, idx  */
            break;                      /* would be word32(-1) and seg fault */
        
        current = &SessionCache[row].Sessions[idx];
        if (XMEMCMP(current->sessionID, id, ID_LEN) == 0) {
            if (LowResTimer() < (current->bornOn + current->timeout)) {
                ret = current;
                if (masterSecret)
                    XMEMCPY(masterSecret, current->masterSecret, SECRET_LEN);
            }
            break;
        }   
    }

    UnLockMutex(&session_mutex);
    
    return ret;
}


int SetSession(CYASSL* ssl, CYASSL_SESSION* session)
{
    if (ssl->options.sessionCacheOff)
        return SSL_FAILURE;

    if (LowResTimer() < (session->bornOn + session->timeout)) {
        ssl->session  = *session;
        ssl->options.resuming = 1;

#ifdef SESSION_CERTS
        ssl->version              = session->version;
        ssl->options.cipherSuite0 = session->cipherSuite0;
        ssl->options.cipherSuite  = session->cipherSuite;
#endif

        return SSL_SUCCESS;
    }
    return SSL_FAILURE;  /* session timed out */
}


int AddSession(CYASSL* ssl)
{
    word32 row, idx;

    if (ssl->options.sessionCacheOff)
        return 0;

    row = HashSession(ssl->arrays.sessionID) % SESSION_ROWS;

    if (LockMutex(&session_mutex) != 0)
        return BAD_MUTEX_ERROR;

    idx = SessionCache[row].nextIdx++;

    XMEMCPY(SessionCache[row].Sessions[idx].masterSecret,
           ssl->arrays.masterSecret, SECRET_LEN);
    XMEMCPY(SessionCache[row].Sessions[idx].sessionID, ssl->arrays.sessionID,
           ID_LEN);

    SessionCache[row].Sessions[idx].timeout = DEFAULT_TIMEOUT;
    SessionCache[row].Sessions[idx].bornOn  = LowResTimer();

#ifdef SESSION_CERTS
    SessionCache[row].Sessions[idx].chain.count = ssl->session.chain.count;
    XMEMCPY(SessionCache[row].Sessions[idx].chain.certs,
           ssl->session.chain.certs, sizeof(x509_buffer) * MAX_CHAIN_DEPTH);

    SessionCache[row].Sessions[idx].version      = ssl->version;
    SessionCache[row].Sessions[idx].cipherSuite0 = ssl->options.cipherSuite0;
    SessionCache[row].Sessions[idx].cipherSuite  = ssl->options.cipherSuite;
#endif

    SessionCache[row].totalCount++;
    if (SessionCache[row].nextIdx == SESSIONS_PER_ROW)
        SessionCache[row].nextIdx = 0;

    if (UnLockMutex(&session_mutex) != 0)
        return BAD_MUTEX_ERROR;

    return 0;
}


    #ifdef SESSION_STATS

    void PrintSessionStats(void)
    {
        word32 totalSessionsSeen = 0;
        word32 totalSessionsNow = 0;
        word32 rowNow;
        int    i;
        double E;               /* expected freq */
        double chiSquare = 0;
        
        for (i = 0; i < SESSION_ROWS; i++) {
            totalSessionsSeen += SessionCache[i].totalCount;

            if (SessionCache[i].totalCount >= SESSIONS_PER_ROW)
                rowNow = SESSIONS_PER_ROW;
            else if (SessionCache[i].nextIdx == 0)
                rowNow = 0;
            else
                rowNow = SessionCache[i].nextIdx;
        
            totalSessionsNow += rowNow;
        }

        printf("Total Sessions Seen = %d\n", totalSessionsSeen);
        printf("Total Sessions Now  = %d\n", totalSessionsNow);

        E = (double)totalSessionsSeen / SESSION_ROWS;

        for (i = 0; i < SESSION_ROWS; i++) {
            double diff = SessionCache[i].totalCount - E;
            diff *= diff;                /* square    */
            diff /= E;                   /* normalize */

            chiSquare += diff;
        }
        printf("  chi-square = %5.1f, d.f. = %d\n", chiSquare,
                                                     SESSION_ROWS - 1);
        if (SESSION_ROWS == 11)
            printf(" .05 p value =  18.3, chi-square should be less\n");
        else if (SESSION_ROWS == 211)
            printf(".05 p value  = 244.8, chi-square should be less\n");
        else if (SESSION_ROWS == 5981)
            printf(".05 p value  = 6161.0, chi-square should be less\n");
        printf("\n");
    }

    #endif /* SESSION_STATS */

#else  /* NO_SESSION_CACHE */

/* No session cache version */
CYASSL_SESSION* GetSession(CYASSL* ssl, byte* masterSecret)
{
    return NULL;  
}

#endif /* NO_SESSION_CACHE */


/* call before SSL_connect, if verifying will add name check to
   date check and signature check */
int CyaSSL_check_domain_name(CYASSL* ssl, const char* dn)
{
    CYASSL_ENTER("CyaSSL_check_domain_name");
    if (ssl->buffers.domainName.buffer)
        XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    ssl->buffers.domainName.length = (word32)XSTRLEN(dn) + 1;
    ssl->buffers.domainName.buffer = (byte*) XMALLOC(
                ssl->buffers.domainName.length, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    if (ssl->buffers.domainName.buffer) {
        XSTRNCPY((char*)ssl->buffers.domainName.buffer, dn,
                ssl->buffers.domainName.length);
        return SSL_SUCCESS;
    }
    else {
        ssl->error = MEMORY_ERROR;
        return SSL_FAILURE;
    }
}


/* turn on CyaSSL zlib compression
   returns 0 for success, else error (not built in)
*/
int CyaSSL_set_compression(CYASSL* ssl)
{
    CYASSL_ENTER("CyaSSL_set_compression");
    (void)ssl;
#ifdef HAVE_LIBZ
    ssl->options.usingCompression = 1;
    return 0;
#else
    return NOT_COMPILED_IN;
#endif
}


#ifndef USE_WINDOWS_API 
    #ifndef NO_WRITEV

        /* simulate writev semantics, doesn't actually do block at a time though
           because of SSL_write behavior and because front adds may be small */
        int CyaSSL_writev(CYASSL* ssl, const struct iovec* iov, int iovcnt)
        {
            byte  tmp[OUTPUT_RECORD_SIZE];
            byte* myBuffer    = tmp;
            int   send      = 0;
            int   newBuffer = 0;
            int   idx       = 0;
            int   i;
            int   ret;

            CYASSL_ENTER("CyaSSL_writev");

            for (i = 0; i < iovcnt; i++)
                send += iov[i].iov_len;

            if (send > (int)sizeof(tmp)) {
                byte* tmp2 = (byte*) XMALLOC(send, ssl->heap,
                                             DYNAMIC_TYPE_WRITEV);
                if (!tmp2)
                    return MEMORY_ERROR;
                myBuffer = tmp2;
                newBuffer = 1;
            }

            for (i = 0; i < iovcnt; i++) {
                XMEMCPY(&myBuffer[idx], iov[i].iov_base, iov[i].iov_len);
                idx += iov[i].iov_len;
            }

            ret = CyaSSL_write(ssl, myBuffer, send);

            if (newBuffer) XFREE(myBuffer, ssl->heap, DYNAMIC_TYPE_WRITEV);

            return ret;
        }
    #endif
#endif


#ifdef CYASSL_CALLBACKS

    typedef struct itimerval Itimerval;

    /* don't keep calling simple functions while setting up timer and singals
       if no inlining these are the next best */

    #define AddTimes(a, b, c)                       \
        do {                                        \
            c.tv_sec  = a.tv_sec  + b.tv_sec;       \
            c.tv_usec = a.tv_usec + b.tv_usec;      \
            if (c.tv_sec >=  1000000) {             \
                c.tv_sec++;                         \
                c.tv_usec -= 1000000;               \
            }                                       \
        } while (0)


    #define SubtractTimes(a, b, c)                  \
        do {                                        \
            c.tv_sec  = a.tv_sec  - b.tv_sec;       \
            c.tv_usec = a.tv_usec - b.tv_usec;      \
            if (c.tv_sec < 0) {                     \
                c.tv_sec--;                         \
                c.tv_usec += 1000000;               \
            }                                       \
        } while (0)

    #define CmpTimes(a, b, cmp)                     \
        ((a.tv_sec  ==  b.tv_sec) ?                 \
            (a.tv_usec cmp b.tv_usec) :             \
            (a.tv_sec  cmp b.tv_sec))               \


    /* do nothing handler */
    static void myHandler(int signo)
    {
        return;
    }


    static int CyaSSL_ex_wrapper(CYASSL* ssl, HandShakeCallBack hsCb,
                                 TimeoutCallBack toCb, Timeval timeout)
    {
        int       ret        = SSL_FATAL_ERROR;
        int       oldTimerOn = 0;   /* was timer already on */
        Timeval   startTime;
        Timeval   endTime;
        Timeval   totalTime;
        Itimerval myTimeout;
        Itimerval oldTimeout; /* if old timer adjust from total time to reset */
        struct sigaction act, oact;
       
        #define ERR_OUT(x) { ssl->hsInfoOn = 0; ssl->toInfoOn = 0; return x; }

        if (hsCb) {
            ssl->hsInfoOn = 1;
            InitHandShakeInfo(&ssl->handShakeInfo);
        }
        if (toCb) {
            ssl->toInfoOn = 1;
            InitTimeoutInfo(&ssl->timeoutInfo);
            
            if (gettimeofday(&startTime, 0) < 0)
                ERR_OUT(GETTIME_ERROR);

            /* use setitimer to simulate getitimer, init 0 myTimeout */
            myTimeout.it_interval.tv_sec  = 0;
            myTimeout.it_interval.tv_usec = 0;
            myTimeout.it_value.tv_sec     = 0;
            myTimeout.it_value.tv_usec    = 0;
            if (setitimer(ITIMER_REAL, &myTimeout, &oldTimeout) < 0)
                ERR_OUT(SETITIMER_ERROR);

            if (oldTimeout.it_value.tv_sec || oldTimeout.it_value.tv_usec) {
                oldTimerOn = 1;
                
                /* is old timer going to expire before ours */
                if (CmpTimes(oldTimeout.it_value, timeout, <)) { 
                    timeout.tv_sec  = oldTimeout.it_value.tv_sec;
                    timeout.tv_usec = oldTimeout.it_value.tv_usec;
                }       
            }
            myTimeout.it_value.tv_sec  = timeout.tv_sec;
            myTimeout.it_value.tv_usec = timeout.tv_usec;
            
            /* set up signal handler, don't restart socket send/recv */
            act.sa_handler = myHandler;
            sigemptyset(&act.sa_mask);
            act.sa_flags = 0;
#ifdef SA_INTERRUPT
            act.sa_flags |= SA_INTERRUPT;
#endif
            if (sigaction(SIGALRM, &act, &oact) < 0)
                ERR_OUT(SIGACT_ERROR);

            if (setitimer(ITIMER_REAL, &myTimeout, 0) < 0)
                ERR_OUT(SETITIMER_ERROR);
        }

        /* do main work */
#ifndef NO_CYASSL_CLIENT
        if (ssl->options.side == CLIENT_END)
            ret = CyaSSL_connect(ssl);
#endif
#ifndef NO_CYASSL_SERVER
        if (ssl->options.side == SERVER_END)
            ret = CyaSSL_accept(ssl);
#endif
       
        /* do callbacks */ 
        if (toCb) {
            if (oldTimerOn) {
                gettimeofday(&endTime, 0);
                SubtractTimes(endTime, startTime, totalTime);
                /* adjust old timer for elapsed time */
                if (CmpTimes(totalTime, oldTimeout.it_value, <))
                    SubtractTimes(oldTimeout.it_value, totalTime,
                                  oldTimeout.it_value);
                else {
                    /* reset value to interval, may be off */
                    oldTimeout.it_value.tv_sec = oldTimeout.it_interval.tv_sec;
                    oldTimeout.it_value.tv_usec =oldTimeout.it_interval.tv_usec;
                }
                /* keep iter the same whether there or not */
            }
            /* restore old handler */
            if (sigaction(SIGALRM, &oact, 0) < 0)
                ret = SIGACT_ERROR;    /* more pressing error, stomp */
            else
                /* use old settings which may turn off (expired or not there) */
                if (setitimer(ITIMER_REAL, &oldTimeout, 0) < 0)
                    ret = SETITIMER_ERROR;
            
            /* if we had a timeout call callback */
            if (ssl->timeoutInfo.timeoutName[0]) {
                ssl->timeoutInfo.timeoutValue.tv_sec  = timeout.tv_sec;
                ssl->timeoutInfo.timeoutValue.tv_usec = timeout.tv_usec;
                (toCb)(&ssl->timeoutInfo);
            }
            /* clean up */
            FreeTimeoutInfo(&ssl->timeoutInfo, ssl->heap);
            ssl->toInfoOn = 0;
        }
        if (hsCb) {
            FinishHandShakeInfo(&ssl->handShakeInfo, ssl);
            (hsCb)(&ssl->handShakeInfo);
            ssl->hsInfoOn = 0;
        }
        return ret;
    }


#ifndef NO_CYASSL_CLIENT

    int CyaSSL_connect_ex(CYASSL* ssl, HandShakeCallBack hsCb,
                          TimeoutCallBack toCb, Timeval timeout)
    {
        CYASSL_ENTER("CyaSSL_connect_ex");
        return CyaSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
    }

#endif


#ifndef NO_CYASSL_SERVER

    int CyaSSL_accept_ex(CYASSL* ssl, HandShakeCallBack hsCb,
                         TimeoutCallBack toCb,Timeval timeout)
    {
        CYASSL_ENTER("CyaSSL_accept_ex");
        return CyaSSL_ex_wrapper(ssl, hsCb, toCb, timeout);
    }

#endif

#endif /* CYASSL_CALLBACKS */


#ifndef NO_PSK

    void CyaSSL_CTX_set_psk_client_callback(CYASSL_CTX* ctx,
                                         psk_client_callback cb)
    {
        CYASSL_ENTER("SSL_CTX_set_psk_client_callback");
        ctx->havePSK = 1;
        ctx->client_psk_cb = cb;
    }


    void CyaSSL_set_psk_client_callback(CYASSL* ssl, psk_client_callback cb)
    {
        CYASSL_ENTER("SSL_set_psk_client_callback");
        ssl->options.havePSK = 1;
        ssl->options.client_psk_cb = cb;

        InitSuites(&ssl->suites, ssl->version,TRUE,TRUE, ssl->options.haveNTRU,
                   ssl->options.haveECDSA, ssl->ctx->method->side);
    }


    void CyaSSL_CTX_set_psk_server_callback(CYASSL_CTX* ctx,
                                         psk_server_callback cb)
    {
        CYASSL_ENTER("SSL_CTX_set_psk_server_callback");
        ctx->havePSK = 1;
        ctx->server_psk_cb = cb;
    }


    void CyaSSL_set_psk_server_callback(CYASSL* ssl, psk_server_callback cb)
    {
        CYASSL_ENTER("SSL_set_psk_server_callback");
        ssl->options.havePSK = 1;
        ssl->options.server_psk_cb = cb;

        InitSuites(&ssl->suites, ssl->version, ssl->options.haveDH, TRUE,
                   ssl->options.haveNTRU, ssl->options.haveECDSA,
                   ssl->ctx->method->side);
    }


    const char* CyaSSL_get_psk_identity_hint(const CYASSL* ssl)
    {
        CYASSL_ENTER("SSL_get_psk_identity_hint");
        return ssl->arrays.server_hint;
    }


    const char* CyaSSL_get_psk_identity(const CYASSL* ssl)
    {
        CYASSL_ENTER("SSL_get_psk_identity");
        return ssl->arrays.client_identity;
    }


    int CyaSSL_CTX_use_psk_identity_hint(CYASSL_CTX* ctx, const char* hint)
    {
        CYASSL_ENTER("SSL_CTX_use_psk_identity_hint");
        if (hint == 0)
            ctx->server_hint[0] = 0;
        else
            XSTRNCPY(ctx->server_hint, hint, MAX_PSK_ID_LEN);
        return SSL_SUCCESS;
    }


    int CyaSSL_use_psk_identity_hint(CYASSL* ssl, const char* hint)
    {
        CYASSL_ENTER("SSL_use_psk_identity_hint");
        if (hint == 0)
            ssl->arrays.server_hint[0] = 0;
        else
            XSTRNCPY(ssl->arrays.server_hint, hint, MAX_PSK_ID_LEN);
        return SSL_SUCCESS;
    }

#endif /* NO_PSK */


/* used to be defined on NO_FILESYSTEM only, but are generally useful */

    /* CyaSSL extension allows DER files to be loaded from buffers as well */
    int CyaSSL_CTX_load_verify_buffer(CYASSL_CTX* ctx, const unsigned char* in,
                                      long sz, int format)
    {
        CYASSL_ENTER("CyaSSL_CTX_load_verify_buffer");
        if (format == SSL_FILETYPE_PEM)
            return ProcessChainBuffer(ctx, in, sz, format, CA_TYPE, NULL);
        else
            return ProcessBuffer(ctx, in, sz, format, CA_TYPE, NULL,NULL,0);
    }


    int CyaSSL_CTX_use_certificate_buffer(CYASSL_CTX* ctx,
                                 const unsigned char* in, long sz, int format)
    {
        CYASSL_ENTER("CyaSSL_CTX_use_certificate_buffer");
        return ProcessBuffer(ctx, in, sz, format, CERT_TYPE, NULL, NULL, 0);
    }


    int CyaSSL_CTX_use_PrivateKey_buffer(CYASSL_CTX* ctx,
                                 const unsigned char* in, long sz, int format)
    {
        CYASSL_ENTER("CyaSSL_CTX_use_PrivateKey_buffer");
        return ProcessBuffer(ctx, in, sz, format, PRIVATEKEY_TYPE, NULL,NULL,0);
    }


    int CyaSSL_CTX_use_certificate_chain_buffer(CYASSL_CTX* ctx,
                                 const unsigned char* in, long sz)
    {
        CYASSL_ENTER("CyaSSL_CTX_use_certificate_chain_buffer");
        return ProcessBuffer(ctx, in, sz, SSL_FILETYPE_PEM, CERT_TYPE, NULL,
                             NULL, 1);
    }

    int CyaSSL_use_certificate_buffer(CYASSL* ssl,
                                 const unsigned char* in, long sz, int format)
    {
        CYASSL_ENTER("CyaSSL_use_certificate_buffer");
        return ProcessBuffer(ssl->ctx, in, sz, format,CERT_TYPE,ssl,NULL,0);
    }


    int CyaSSL_use_PrivateKey_buffer(CYASSL* ssl,
                                 const unsigned char* in, long sz, int format)
    {
        CYASSL_ENTER("CyaSSL_use_PrivateKey_buffer");
        return ProcessBuffer(ssl->ctx, in, sz, format, PRIVATEKEY_TYPE, 
                             ssl, NULL, 0);
    }


    int CyaSSL_use_certificate_chain_buffer(CYASSL* ssl,
                                 const unsigned char* in, long sz)
    {
        CYASSL_ENTER("CyaSSL_use_certificate_chain_buffer");
        return ProcessBuffer(ssl->ctx, in, sz, SSL_FILETYPE_PEM, CERT_TYPE,
                             ssl, NULL, 1);
    }

/* old NO_FILESYSTEM end */


#if defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)


    int CyaSSL_add_all_algorithms(void)
    {
        CYASSL_ENTER("CyaSSL_add_all_algorithms");
        CyaSSL_Init();
        return SSL_SUCCESS;
    }


    long CyaSSL_CTX_sess_set_cache_size(CYASSL_CTX* ctx, long sz)
    {
        /* cache size fixed at compile time in CyaSSL */
        (void)ctx;
        (void)sz;
        return 0;
    }


    void CyaSSL_CTX_set_quiet_shutdown(CYASSL_CTX* ctx, int mode)
    {
        CYASSL_ENTER("CyaSSL_CTX_set_quiet_shutdown");
        if (mode)
            ctx->quietShutdown = 1;
    }


    void CyaSSL_set_quiet_shutdown(CYASSL* ssl, int mode)
    {
        CYASSL_ENTER("CyaSSL_CTX_set_quiet_shutdown");
        if (mode)
            ssl->options.quietShutdown = 1;
    }


    int CyaSSL_CTX_check_private_key(CYASSL_CTX* ctx)
    {
        /* TODO: check private against public for RSA match */
        (void)ctx; 
        CYASSL_ENTER("SSL_CTX_check_private_key");
        return SSL_SUCCESS;
    }


    void CyaSSL_set_bio(CYASSL* ssl, CYASSL_BIO* rd, CYASSL_BIO* wr)
    {
        CYASSL_ENTER("SSL_set_bio");
        CyaSSL_set_rfd(ssl, rd->fd);
        CyaSSL_set_wfd(ssl, wr->fd);

        ssl->biord = rd;
        ssl->biowr = wr;
    }


    void CyaSSL_CTX_set_client_CA_list(CYASSL_CTX* ctx,
                                       STACK_OF(CYASSL_X509_NAME)* names)
    {
        (void)ctx; 
        (void)names; 
    }


    STACK_OF(CYASSL_X509_NAME)* CyaSSL_load_client_CA_file(const char* fname)
    {
        (void)fname;
        return 0;
    }


    int CyaSSL_CTX_set_default_verify_paths(CYASSL_CTX* ctx)
    {
        /* TODO:, not needed in goahead */
        (void)ctx; 
        return SSL_NOT_IMPLEMENTED;
    }


    /* keyblock size in bytes or -1 */
    int CyaSSL_get_keyblock_size(CYASSL* ssl)
    {
        if (ssl == NULL)
            return -1;

        return 2 * (ssl->specs.key_size + ssl->specs.iv_size +
                    ssl->specs.hash_size);
    }


    /* store keys returns 0 or -1 on error */
    int CyaSSL_get_keys(CYASSL* ssl, unsigned char** ms, unsigned int* msLen,
                                     unsigned char** sr, unsigned int* srLen,
                                     unsigned char** cr, unsigned int* crLen)
    {
        if (ssl == NULL)
            return -1;

        *ms = ssl->arrays.masterSecret;
        *sr = ssl->arrays.serverRandom;
        *cr = ssl->arrays.clientRandom;

        *msLen = SECRET_LEN;
        *srLen = RAN_LEN;
        *crLen = RAN_LEN;
    
        return 0;
    }


    void CyaSSL_set_accept_state(CYASSL* ssl)
    {
        byte havePSK = 0;

        CYASSL_ENTER("SSL_set_accept_state");
        ssl->options.side = SERVER_END;
        /* reset suites in case user switched */
#ifndef NO_PSK
        havePSK = ssl->options.havePSK;
#endif
        InitSuites(&ssl->suites, ssl->version, ssl->options.haveDH, havePSK,
                   ssl->options.haveNTRU, ssl->options.haveECDSA,
                   ssl->ctx->method->side);
    }

   
    /* return true if connection established */
    int CyaSSL_is_init_finished(CYASSL* ssl)
    {
        if (ssl == NULL)
            return 0;

        if (ssl->options.handShakeState == HANDSHAKE_DONE)
            return 1;

        return 0;
    }


    void CyaSSL_CTX_set_tmp_rsa_callback(CYASSL_CTX* ctx,
                                      CYASSL_RSA*(*f)(CYASSL*, int, int))
    {
        /* CyaSSL verifies all these internally */   
        (void)ctx; 
        (void)f; 
    }


    void CyaSSL_set_shutdown(CYASSL* ssl, int opt)
    {
        (void)ssl; 
        (void)opt; 
    }


    long CyaSSL_CTX_set_options(CYASSL_CTX* ctx, long opt)
    {
        /* goahead calls with 0, do nothing */ 
        CYASSL_ENTER("SSL_CTX_set_options");
        (void)ctx; 
        return opt;
    }


    int CyaSSL_set_rfd(CYASSL* ssl, int rfd)
    {
        CYASSL_ENTER("SSL_set_rfd");
        ssl->rfd = rfd;      /* not used directly to allow IO callbacks */

        ssl->IOCB_ReadCtx  = &ssl->rfd;

        return SSL_SUCCESS;
    }


    int CyaSSL_set_wfd(CYASSL* ssl, int wfd)
    {
        CYASSL_ENTER("SSL_set_wfd");
        ssl->wfd = wfd;      /* not used directly to allow IO callbacks */

        ssl->IOCB_WriteCtx  = &ssl->wfd;

        return SSL_SUCCESS;
    }


    CYASSL_RSA* CyaSSL_RSA_generate_key(int len, unsigned long bits,
                                          void(*f)(int, int, void*), void* data)
    {
        /* no tmp key needed, actual generation not supported */
        CYASSL_ENTER("RSA_generate_key");
        (void)len; 
        (void)bits; 
        (void)f; 
        (void)data; 
        return 0;
    }


    CYASSL_X509_NAME* CyaSSL_X509_get_issuer_name(CYASSL_X509* cert)
    {
        CYASSL_ENTER("X509_get_issuer_name");
        return &cert->issuer;
    }


    CYASSL_X509_NAME* CyaSSL_X509_get_subject_name(CYASSL_X509* cert)
    {
        CYASSL_ENTER("X509_get_subject_name");
        return &cert->subject;
    }


    /* copy name into in buffer, at most sz bytes, if buffer is null will
       malloc buffer, call responsible for freeing                     */
    char* CyaSSL_X509_NAME_oneline(CYASSL_X509_NAME* name, char* in, int sz)
    {
        int copySz = min(sz, name->sz);

        CYASSL_ENTER("CyaSSL_X509_NAME_oneline");
        if (!name->sz) return in;

        if (!in) {
            in = (char*)XMALLOC(name->sz, 0, DYNAMIC_TYPE_OPENSSL);
            if (!in ) return in;
            copySz = name->sz;
        }

        if (copySz == 0)
            return in;

        XMEMCPY(in, name->name, copySz - 1);
        in[copySz - 1] = 0;

        return in;
    }


    CYASSL_X509* CyaSSL_X509_STORE_CTX_get_current_cert(
                                                     CYASSL_X509_STORE_CTX* ctx)
    {
        (void)ctx; 
        return 0;
    }


    int CyaSSL_X509_STORE_CTX_get_error(CYASSL_X509_STORE_CTX* ctx)
    {
        (void)ctx; 
        return 0;
    }


    int CyaSSL_X509_STORE_CTX_get_error_depth(CYASSL_X509_STORE_CTX* ctx)
    {
        (void)ctx; 
        return 0;
    }


    CYASSL_BIO_METHOD* CyaSSL_BIO_f_buffer(void)
    {
        static CYASSL_BIO_METHOD meth;

        CYASSL_ENTER("BIO_f_buffer");
        meth.type = BIO_BUFFER;

        return &meth;
    }


    long CyaSSL_BIO_set_write_buffer_size(CYASSL_BIO* bio, long size)
    {
        /* CyaSSL has internal buffer, compatibility only */
        CYASSL_ENTER("BIO_set_write_buffer_size");
        (void)bio; 
        return size; 
    }


    CYASSL_BIO_METHOD* CyaSSL_BIO_f_ssl(void)
    {
        static CYASSL_BIO_METHOD meth;

        CYASSL_ENTER("BIO_f_ssl");
        meth.type = BIO_SSL;

        return &meth;
    }


    CYASSL_BIO* CyaSSL_BIO_new_socket(int sfd, int closeF)
    {
        CYASSL_BIO* bio = (CYASSL_BIO*) XMALLOC(sizeof(CYASSL_BIO), 0,
                                                DYNAMIC_TYPE_OPENSSL);

        CYASSL_ENTER("BIO_new_socket");
        if (bio) { 
            bio->type  = BIO_SOCKET;
            bio->close = (byte)closeF;
            bio->eof   = 0;
            bio->ssl   = 0;
            bio->fd    = sfd;
            bio->prev  = 0;
            bio->next  = 0;
        }
        return bio; 
    }


    int CyaSSL_BIO_eof(CYASSL_BIO* b)
    {
        CYASSL_ENTER("BIO_eof");
        if (b->eof)
            return 1;

        return 0;        
    }


    long CyaSSL_BIO_set_ssl(CYASSL_BIO* b, CYASSL* ssl, int closeF)
    {
        CYASSL_ENTER("BIO_set_ssl");
        b->ssl   = ssl;
        b->close = (byte)closeF;
    /* add to ssl for bio free if SSL_free called before/instead of free_all? */

        return 0;
    }


    CYASSL_BIO* CyaSSL_BIO_new(CYASSL_BIO_METHOD* method)
    {
        CYASSL_BIO* bio = (CYASSL_BIO*) XMALLOC(sizeof(CYASSL_BIO), 0,
                                                DYNAMIC_TYPE_OPENSSL);
        CYASSL_ENTER("BIO_new");
        if (bio) {
            bio->type  = method->type;
            bio->close = 0;
            bio->eof   = 0;
            bio->ssl   = 0;
            bio->fd    = 0;
            bio->prev  = 0;
            bio->next  = 0;
        }
        return bio;
    }


#ifdef USE_WINDOWS_API 
    #define CloseSocket(s) closesocket(s)
#else
    #define CloseSocket(s) close(s)
#endif

    int CyaSSL_BIO_free(CYASSL_BIO* bio)
    {
        /* unchain?, doesn't matter in goahead since from free all */
        CYASSL_ENTER("BIO_free");
        if (bio) {
            if (bio->close) {
                if (bio->ssl)
                    CyaSSL_free(bio->ssl);
                if (bio->fd)
                    CloseSocket(bio->fd);
            }
            XFREE(bio, 0, DYNAMIC_TYPE_OPENSSL);
        }
        return 0;
    }


    int CyaSSL_BIO_free_all(CYASSL_BIO* bio)
    {
        CYASSL_ENTER("BIO_free_all");
        while (bio) {
            CYASSL_BIO* next = bio->next;
            CyaSSL_BIO_free(bio);
            bio = next;
        }
        return 0;
    }


    int CyaSSL_BIO_read(CYASSL_BIO* bio, void* buf, int len)
    {
        int  ret;
        CYASSL* ssl = 0;
        CYASSL_BIO* front = bio;

        CYASSL_ENTER("BIO_read");
        /* already got eof, again is error */
        if (front->eof)
            return SSL_FATAL_ERROR;

        while(bio && ((ssl = bio->ssl) == 0) )
            bio = bio->next;

        if (ssl == 0) return BAD_FUNC_ARG;

        ret = CyaSSL_read(ssl, buf, len);
        if (ret == 0)
            front->eof = 1;
        else if (ret < 0) {
            int err = CyaSSL_get_error(ssl, 0);
            if ( !(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) )
                front->eof = 1;
        }
        return ret;
    }


    int CyaSSL_BIO_write(CYASSL_BIO* bio, const void* data, int len)
    {
        int  ret;
        CYASSL* ssl = 0;
        CYASSL_BIO* front = bio;

        CYASSL_ENTER("BIO_write");
        /* already got eof, again is error */
        if (front->eof)
            return SSL_FATAL_ERROR;

        while(bio && ((ssl = bio->ssl) == 0) )
            bio = bio->next;

        if (ssl == 0) return BAD_FUNC_ARG;

        ret = CyaSSL_write(ssl, data, len);
        if (ret == 0)
            front->eof = 1;
        else if (ret < 0) {
            int err = CyaSSL_get_error(ssl, 0);
            if ( !(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) )
                front->eof = 1;
        }

        return ret;
    }


    CYASSL_BIO* CyaSSL_BIO_push(CYASSL_BIO* top, CYASSL_BIO* append)
    {
        CYASSL_ENTER("BIO_push");
        top->next    = append;
        append->prev = top;

        return top;
    }


    int CyaSSL_BIO_flush(CYASSL_BIO* bio)
    {
        /* for CyaSSL no flushing needed */
        CYASSL_ENTER("BIO_flush");
        (void)bio; 
        return 1;
    }


#endif /* OPENSSL_EXTRA || GOAHEAD_WS */


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

    void CyaSSL_CTX_set_default_passwd_cb_userdata(CYASSL_CTX* ctx,
                                                   void* userdata)
    {
        CYASSL_ENTER("SSL_CTX_set_default_passwd_cb_userdata");
        ctx->userdata = userdata;
    }


    void CyaSSL_CTX_set_default_passwd_cb(CYASSL_CTX* ctx, pem_password_cb cb)
    {
        CYASSL_ENTER("SSL_CTX_set_default_passwd_cb");
        ctx->passwd_cb = cb;
    }

    int CyaSSL_num_locks(void)
    {
        return 0;
    }

    void CyaSSL_set_locking_callback(void (*f)(int, int, const char*, int))
    {
        (void)f; 
    }

    void CyaSSL_set_id_callback(unsigned long (*f)(void))
    {
        (void)f; 
    }

    unsigned long CyaSSL_ERR_get_error(void)
    {
        /* TODO: */
        return 0;
    }

    int CyaSSL_EVP_BytesToKey(const CYASSL_EVP_CIPHER* type,
                       const CYASSL_EVP_MD* md, const byte* salt,
                       const byte* data, int sz, int count, byte* key, byte* iv)
    {
        int keyLen = 0;
        int ivLen  = 0;

        Md5    myMD;
        byte   digest[MD5_DIGEST_SIZE];

        int j;
        int keyLeft;
        int ivLeft;
        int keyOutput = 0;

        CYASSL_ENTER("EVP_BytesToKey");
        InitMd5(&myMD);

        /* only support MD5 for now */
        if (XSTRNCMP(md, "MD5", 3)) return 0;

        /* only support CBC DES and AES for now */
        if (XSTRNCMP(type, "DES-CBC", 7) == 0) {
            keyLen = DES_KEY_SIZE;
            ivLen  = DES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "DES-EDE3-CBC", 12) == 0) {
            keyLen = DES3_KEY_SIZE;
            ivLen  = DES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "AES-128-CBC", 11) == 0) {
            keyLen = AES_128_KEY_SIZE;
            ivLen  = AES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "AES-192-CBC", 11) == 0) {
            keyLen = AES_192_KEY_SIZE;
            ivLen  = AES_IV_SIZE;
        }
        else if (XSTRNCMP(type, "AES-256-CBC", 11) == 0) {
            keyLen = AES_256_KEY_SIZE;
            ivLen  = AES_IV_SIZE;
        }
        else
            return 0;

        keyLeft   = keyLen;
        ivLeft    = ivLen;

        while (keyOutput < (keyLen + ivLen)) {
            int digestLeft = MD5_DIGEST_SIZE;
            /* D_(i - 1) */
            if (keyOutput)                      /* first time D_0 is empty */
                Md5Update(&myMD, digest, MD5_DIGEST_SIZE);
            /* data */
            Md5Update(&myMD, data, sz);
            /* salt */
            if (salt)
                Md5Update(&myMD, salt, EVP_SALT_SIZE);
            Md5Final(&myMD, digest);
            /* count */
            for (j = 1; j < count; j++) {
                Md5Update(&myMD, digest, MD5_DIGEST_SIZE);
                Md5Final(&myMD, digest);
            }

            if (keyLeft) {
                int store = min(keyLeft, MD5_DIGEST_SIZE);
                XMEMCPY(&key[keyLen - keyLeft], digest, store);

                keyOutput  += store;
                keyLeft    -= store;
                digestLeft -= store;
            }

            if (ivLeft && digestLeft) {
                int store = min(ivLeft, digestLeft);
                XMEMCPY(&iv[ivLen - ivLeft], &digest[MD5_DIGEST_SIZE -
                                                    digestLeft], store);
                keyOutput += store;
                ivLeft    -= store;
            }
        }
        if (keyOutput != (keyLen + ivLen))
            return 0;
        return keyOutput;
    }

#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */


#ifdef OPENSSL_EXTRA

    unsigned long CyaSSLeay(void)
    {
        return SSLEAY_VERSION_NUMBER;
    }


    const char* CyaSSLeay_version(int type)
    {
        static const char* version = "SSLeay CyaSSL compatibility";
        (void)type; 
        return version;
    }


    void CyaSSL_MD5_Init(CYASSL_MD5_CTX* md5)
    {
        typedef char md5_test[sizeof(MD5_CTX) >= sizeof(Md5) ? 1 : -1];
        (void)sizeof(md5_test);

        CYASSL_ENTER("MD5_Init");
        InitMd5((Md5*)md5);
    }


    void CyaSSL_MD5_Update(CYASSL_MD5_CTX* md5, const void* input,
                           unsigned long sz)
    {
        CYASSL_ENTER("CyaSSL_MD5_Update");
        Md5Update((Md5*)md5, (const byte*)input, sz);
    }


    void CyaSSL_MD5_Final(byte* input, CYASSL_MD5_CTX* md5)
    {
        CYASSL_ENTER("MD5_Final");
        Md5Final((Md5*)md5, input);
    }


    void CyaSSL_SHA_Init(CYASSL_SHA_CTX* sha)
    {
        typedef char sha_test[sizeof(SHA_CTX) >= sizeof(Sha) ? 1 : -1];
        (void)sizeof(sha_test);

        CYASSL_ENTER("SHA_Init");
        InitSha((Sha*)sha);
    }


    void CyaSSL_SHA_Update(CYASSL_SHA_CTX* sha, const void* input,
                           unsigned long sz)
    {
        CYASSL_ENTER("SHA_Update");
        ShaUpdate((Sha*)sha, (const byte*)input, sz);
    }


    void CyaSSL_SHA_Final(byte* input, CYASSL_SHA_CTX* sha)
    {
        CYASSL_ENTER("SHA_Final");
        ShaFinal((Sha*)sha, input);
    }


    void CyaSSL_SHA1_Init(CYASSL_SHA_CTX* sha)
    {
        CYASSL_ENTER("SHA1_Init");
        SHA_Init(sha);
    }


    void CyaSSL_SHA1_Update(CYASSL_SHA_CTX* sha, const void* input,
                            unsigned long sz)
    {
        CYASSL_ENTER("SHA1_Update");
        SHA_Update(sha, input, sz);
    }


    void CyaSSL_SHA1_Final(byte* input, CYASSL_SHA_CTX* sha)
    {
        CYASSL_ENTER("SHA1_Final");
        SHA_Final(input, sha);
    }


    const CYASSL_EVP_MD* CyaSSL_EVP_md5(void)
    {
        static const char* type = "MD5";
        CYASSL_ENTER("EVP_md5");
        return type;
    }


    const CYASSL_EVP_MD* CyaSSL_EVP_sha1(void)
    {
        static const char* type = "SHA";
        CYASSL_ENTER("EVP_sha1");
        return type;
    }


    void CyaSSL_EVP_MD_CTX_init(CYASSL_EVP_MD_CTX* ctx)
    {
        (void)ctx; 
        /* do nothing */ 
    }


    int CyaSSL_EVP_MD_CTX_cleanup(CYASSL_EVP_MD_CTX* ctx)
    {
        CYASSL_ENTER("EVP_MD_CTX_cleanup");
        (void)ctx; 
        return 0;
    }    


    int CyaSSL_EVP_DigestInit(CYASSL_EVP_MD_CTX* ctx, const CYASSL_EVP_MD* type)
    {
        CYASSL_ENTER("EVP_DigestInit");
        if (XSTRNCMP(type, "MD5", 3) == 0) {
             ctx->macType = MD5;
             CyaSSL_MD5_Init((MD5_CTX*)&ctx->hash);
        }
        else if (XSTRNCMP(type, "SHA", 3) == 0) {
             ctx->macType = SHA;
             CyaSSL_SHA_Init((SHA_CTX*)&ctx->hash);
        }
        else
             return BAD_FUNC_ARG;

        return 0;
    }


    int CyaSSL_EVP_DigestUpdate(CYASSL_EVP_MD_CTX* ctx, const void* data,
                                unsigned long sz)
    {
        CYASSL_ENTER("EVP_DigestUpdate");
        if (ctx->macType == MD5) 
            CyaSSL_MD5_Update((MD5_CTX*)&ctx->hash, data, (unsigned long)sz);
        else if (ctx->macType == SHA) 
            CyaSSL_SHA_Update((SHA_CTX*)&ctx->hash, data, (unsigned long)sz);
        else
            return BAD_FUNC_ARG;

        return 0;
    }


    int CyaSSL_EVP_DigestFinal(CYASSL_EVP_MD_CTX* ctx, unsigned char* md,
                               unsigned int* s)
    {
        CYASSL_ENTER("EVP_DigestFinal");
        if (ctx->macType == MD5) {
            CyaSSL_MD5_Final(md, (MD5_CTX*)&ctx->hash);
            if (s) *s = MD5_DIGEST_SIZE;
        }
        else if (ctx->macType == SHA) {
            CyaSSL_SHA_Final(md, (SHA_CTX*)&ctx->hash);
            if (s) *s = SHA_DIGEST_SIZE;
        }
        else
            return BAD_FUNC_ARG;

        return 0;
    }


    int CyaSSL_EVP_DigestFinal_ex(CYASSL_EVP_MD_CTX* ctx, unsigned char* md,
                                  unsigned int* s)
    {
        CYASSL_ENTER("EVP_DigestFinal_ex");
        return EVP_DigestFinal(ctx, md, s);
    }


    unsigned char* CyaSSL_HMAC(const CYASSL_EVP_MD* evp_md, const void* key,
                               int key_len, const unsigned char* d, int n,
                               unsigned char* md, unsigned int* md_len)
    {
        Hmac hmac;

        CYASSL_ENTER("HMAC");
        if (!md) return 0;  /* no static buffer support */

        if (XSTRNCMP(evp_md, "MD5", 3) == 0) {
            HmacSetKey(&hmac, MD5, key, key_len);
            if (md_len) *md_len = MD5_DIGEST_SIZE;
        }
        else if (XSTRNCMP(evp_md, "SHA", 3) == 0) {
            HmacSetKey(&hmac, SHA, key, key_len);    
            if (md_len) *md_len = SHA_DIGEST_SIZE;
        }
        else
            return 0;

        HmacUpdate(&hmac, d, n);
        HmacFinal(&hmac, md);
    
        return md;
    }

    void CyaSSL_ERR_clear_error(void)
    {
        /* TODO: */
    }


    int CyaSSL_RAND_status(void)
    {
        return 1;  /* CTaoCrypt provides enough seed internally */
    }


    int CyaSSL_RAND_bytes(unsigned char* buf, int num)
    {
        RNG rng;

        CYASSL_ENTER("RAND_bytes");
        if (InitRng(&rng))
           return 0;

        RNG_GenerateBlock(&rng, buf, num);

        return 1;
    }


    int CyaSSL_DES_key_sched(CYASSL_const_DES_cblock* key,
                             CYASSL_DES_key_schedule* schedule)
    {
        CYASSL_ENTER("DES_key_sched");
        XMEMCPY(schedule, key, sizeof(const_DES_cblock));
        return 0;
    }


    void CyaSSL_DES_cbc_encrypt(const unsigned char* input,
                     unsigned char* output, long length,
                     CYASSL_DES_key_schedule* schedule, CYASSL_DES_cblock* ivec,
                     int enc)
    {
        Des myDes;
        CYASSL_ENTER("DES_cbc_encrypt");
        Des_SetKey(&myDes, (const byte*)schedule, (const byte*)ivec, !enc);

        if (enc)
            Des_CbcEncrypt(&myDes, output, input, length);
        else
            Des_CbcDecrypt(&myDes, output, input, length);
    }


    /* correctly sets ivec for next call */
    void CyaSSL_DES_ncbc_encrypt(const unsigned char* input,
                     unsigned char* output, long length,
                     CYASSL_DES_key_schedule* schedule, CYASSL_DES_cblock* ivec,
                     int enc)
    {
        Des myDes;
        CYASSL_ENTER("DES_ncbc_encrypt");
        Des_SetKey(&myDes, (const byte*)schedule, (const byte*)ivec, !enc);

        if (enc)
            Des_CbcEncrypt(&myDes, output, input, length);
        else
            Des_CbcDecrypt(&myDes, output, input, length);

        XMEMCPY(ivec, output + length - sizeof(DES_cblock), sizeof(DES_cblock));
    }


    void CyaSSL_ERR_free_strings(void)
    {
        /* handled internally */
    }


    void CyaSSL_ERR_remove_state(unsigned long state)
    {
        /* TODO: GetErrors().Remove(); */
        (void)state; 
    }


    void CyaSSL_EVP_cleanup(void)
    {
        /* nothing to do here */
    }


    void CyaSSL_cleanup_all_ex_data(void)
    {
        /* nothing to do here */
    }


    long CyaSSL_CTX_set_mode(CYASSL_CTX* ctx, long mode)
    {
        /* SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is CyaSSL default mode */

        CYASSL_ENTER("SSL_CTX_set_mode");
        if (mode == SSL_MODE_ENABLE_PARTIAL_WRITE)
            ctx->partialWrite = 1;

        return mode;
    }


    long CyaSSL_CTX_get_mode(CYASSL_CTX* ctx)
    {
        /* TODO: */
        (void)ctx; 
        return 0;
    }


    void CyaSSL_CTX_set_default_read_ahead(CYASSL_CTX* ctx, int m)
    {
        /* TODO: maybe? */
        (void)ctx; 
        (void)m; 
    }


    int CyaSSL_CTX_set_session_id_context(CYASSL_CTX* ctx,
                                       const unsigned char* sid_ctx,
                                       unsigned int sid_ctx_len)
    {
        /* No application specific context needed for cyaSSL */
        (void)ctx; 
        (void)sid_ctx; 
        (void)sid_ctx_len; 
        return SSL_SUCCESS;
    }


    long CyaSSL_CTX_sess_get_cache_size(CYASSL_CTX* ctx)
    {
        /* TODO: maybe? */
        (void)ctx; 
        return (~0);
    }

    unsigned long CyaSSL_ERR_get_error_line_data(const char** file, int* line,
                                          const char** data, int *flags)
    {
        /* Not implemented */
        (void)file; 
        (void)line; 
        (void)data; 
        (void)flags; 
        return 0;
    }


    CYASSL_X509* CyaSSL_get_peer_certificate(CYASSL* ssl)
    {
        CYASSL_ENTER("SSL_get_peer_certificate");
        if (ssl->peerCert.issuer.sz)
            return &ssl->peerCert;
        else
            return 0;
    }



    int CyaSSL_set_ex_data(CYASSL* ssl, int idx, void* data)
    {
        (void)ssl;
        (void)idx;
        (void)data;
        return 0;
    }


    int CyaSSL_get_shutdown(const CYASSL* ssl)
    {
        (void)ssl;
        return 0;
    }


    int CyaSSL_set_session_id_context(CYASSL* ssl, const unsigned char* id,
                                   unsigned int len)
    {
        (void)ssl;
        (void)id;
        (void)len;
        return 0;
    }


    void CyaSSL_set_connect_state(CYASSL* ssl)
    {
        (void)ssl;
        /* client by default */ 
    }


    int CyaSSL_session_reused(CYASSL* ssl)
    {
        return ssl->options.resuming;
    }


    void CyaSSL_SESSION_free(CYASSL_SESSION* session)
    {
        (void)session;
    }


    const char* CyaSSL_get_version(CYASSL* ssl)
    {
        CYASSL_ENTER("SSL_get_version");
        if (ssl->version.major == SSLv3_MAJOR) {
            switch (ssl->version.minor) {
                case SSLv3_MINOR :
                    return "SSLv3";
                case TLSv1_MINOR :
                    return "TLSv1";
                case TLSv1_1_MINOR :
                    return "TLSv1.1";
                case TLSv1_2_MINOR :
                    return "TLSv1.2";
                default:
                    return "unknown";
            }
        }
        else if (ssl->version.major == DTLS_MAJOR)
            return "DTLS";
        return "unknown";
    }


    CYASSL_CIPHER*  CyaSSL_get_current_cipher(CYASSL* ssl)
    {
        CYASSL_ENTER("SSL_get_current_cipher");
        return &ssl->cipher;
    }


    const char* CyaSSL_CIPHER_get_name(const CYASSL_CIPHER* cipher)
    {
        CYASSL_ENTER("SSL_CIPHER_get_name");
        if (cipher) {
#ifdef HAVE_ECC
            if (cipher->ssl->options.cipherSuite0 == ECC_BYTE) {
            /* ECC suites */
            switch (cipher->ssl->options.cipherSuite) {
                case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
                    return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
                case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
                    return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
                case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :
                    return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
                case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :
                    return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
                case TLS_ECDHE_RSA_WITH_RC4_128_SHA :
                    return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
                case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA :
                    return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
                case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :
                    return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
                case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :
                    return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
                default:
                    return "NONE";
            }
            }
#endif
            if (cipher->ssl->options.cipherSuite0 != ECC_BYTE) {
            /* normal suites */
            switch (cipher->ssl->options.cipherSuite) {
                case SSL_RSA_WITH_RC4_128_SHA :
                    return "SSL_RSA_WITH_RC4_128_SHA";
                case SSL_RSA_WITH_RC4_128_MD5 :
                    return "SSL_RSA_WITH_RC4_128_MD5";
                case SSL_RSA_WITH_3DES_EDE_CBC_SHA :
                    return "SSL_RSA_WITH_3DES_EDE_CBC_SHA";
                case TLS_RSA_WITH_AES_128_CBC_SHA :
                    return "TLS_RSA_WITH_AES_128_CBC_SHA";
                case TLS_RSA_WITH_AES_256_CBC_SHA :
                    return "TLS_RSA_WITH_AES_256_CBC_SHA";
                case TLS_RSA_WITH_AES_128_CBC_SHA256 :
                    return "TLS_RSA_WITH_AES_128_CBC_SHA256";
                case TLS_RSA_WITH_AES_256_CBC_SHA256 :
                    return "TLS_RSA_WITH_AES_256_CBC_SHA256";
                case TLS_PSK_WITH_AES_128_CBC_SHA :
                    return "TLS_PSK_WITH_AES_128_CBC_SHA";
                case TLS_PSK_WITH_AES_256_CBC_SHA :
                    return "TLS_PSK_WITH_AES_256_CBC_SHA";
                case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :
                    return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
                case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :
                    return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
                case TLS_DHE_RSA_WITH_AES_128_CBC_SHA :
                    return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
                case TLS_DHE_RSA_WITH_AES_256_CBC_SHA :
                    return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
                case TLS_RSA_WITH_HC_128_CBC_MD5 :
                    return "TLS_RSA_WITH_HC_128_CBC_MD5";
                case TLS_RSA_WITH_HC_128_CBC_SHA :
                    return "TLS_RSA_WITH_HC_128_CBC_SHA";
                case TLS_RSA_WITH_RABBIT_CBC_SHA :
                    return "TLS_RSA_WITH_RABBIT_CBC_SHA";
                case TLS_NTRU_RSA_WITH_RC4_128_SHA :
                    return "TLS_NTRU_RSA_WITH_RC4_128_SHA";
                case TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA :
                    return "TLS_NTRU_RSA_WITH_3DES_EDE_CBC_SHA";
                case TLS_NTRU_RSA_WITH_AES_128_CBC_SHA :
                    return "TLS_NTRU_RSA_WITH_AES_128_CBC_SHA";
                case TLS_NTRU_RSA_WITH_AES_256_CBC_SHA :
                    return "TLS_NTRU_RSA_WITH_AES_256_CBC_SHA";
                default:
                    return "NONE";
            }  /* switch */
            }  /* normal / ECC */
        }

        return "NONE";
    }


    /* server ctx Diffie-Hellman parameters */
    int CyaSSL_CTX_SetTmpDH(CYASSL_CTX* ctx, const unsigned char* p, int pSz,
                            const unsigned char* g, int gSz)
    {
        CYASSL_ENTER("CyaSSL_CTX_SetTmpDH");
        if (ctx == NULL || p == NULL || g == NULL) return BAD_FUNC_ARG;

        XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
        XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_DH);

        ctx->serverDH_P.buffer = (byte*)XMALLOC(pSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_P.buffer == NULL)
            return MEMORY_E;

        ctx->serverDH_G.buffer = (byte*)XMALLOC(gSz, ctx->heap,DYNAMIC_TYPE_DH);
        if (ctx->serverDH_G.buffer == NULL) {
            XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_DH);
            return MEMORY_E;
        }

        ctx->serverDH_P.length = pSz;
        ctx->serverDH_G.length = gSz;

        XMEMCPY(ctx->serverDH_P.buffer, p, pSz);
        XMEMCPY(ctx->serverDH_G.buffer, g, gSz);

        ctx->haveDH = 1;

        CYASSL_LEAVE("CyaSSL_CTX_SetTmpDH", 0);
        return 0;
    }


    char* CyaSSL_CIPHER_description(CYASSL_CIPHER* cipher, char* in, int len)
    {
        (void)cipher;
        (void)in;
        (void)len;
        return 0;
    }


    CYASSL_SESSION* CyaSSL_get1_session(CYASSL* ssl)  /* what's ref count */
    {
        (void)ssl;
        return 0;
    }


    void CyaSSL_X509_free(CYASSL_X509* buf)
    {
        (void)buf;
    }


    /* was do nothing */
    /*
    void OPENSSL_free(void* buf)
    {
        (void)buf;
    }
    */


    int CyaSSL_OCSP_parse_url(char* url, char** host, char** port, char** path,
                       int* ssl)
    {
        (void)url;
        (void)host;
        (void)port;
        (void)path;
        (void)ssl;
        return 0;
    }


    CYASSL_METHOD* CyaSSLv2_client_method(void)
    {
        return 0;
    }


    CYASSL_METHOD* CyaSSLv2_server_method(void)
    {
        return 0;
    }


#ifndef NO_MD4

    void CyaSSL_MD4_Init(CYASSL_MD4_CTX* md4)
    {
        /* make sure we have a big enough buffer */
        typedef char ok[sizeof(md4->buffer) >= sizeof(Md4) ? 1 : -1];
        (void) sizeof(ok);
 
        CYASSL_ENTER("MD4_Init");
        InitMd4((Md4*)md4);    
    }


    void CyaSSL_MD4_Update(CYASSL_MD4_CTX* md4, const void* data,
                           unsigned long len)
    {
        CYASSL_ENTER("MD4_Update");
        Md4Update((Md4*)md4, (const byte*)data, (word32)len); 
    }


    void CyaSSL_MD4_Final(unsigned char* digest, CYASSL_MD4_CTX* md4)
    {
        CYASSL_ENTER("MD4_Final");
        Md4Final((Md4*)md4, digest); 
    }

#endif /* NO_MD4 */


    CYASSL_BIO* CyaSSL_BIO_pop(CYASSL_BIO* top)
    {
        (void)top;
        return 0;
    }


    int CyaSSL_BIO_pending(CYASSL_BIO* bio)
    {
        (void)bio;
        return 0;
    }



    CYASSL_BIO_METHOD* CyaSSL_BIO_s_mem(void)
    {
        return 0;
    }


    CYASSL_BIO_METHOD* CyaSSL_BIO_f_base64(void)
    {
        return 0;
    }


    void CyaSSL_BIO_set_flags(CYASSL_BIO* bio, int flags)
    {
        (void)bio;
        (void)flags;
    }



    void CyaSSL_RAND_screen(void)
    {
    
    }


    const char* CyaSSL_RAND_file_name(char* fname, unsigned long len)
    {
        (void)fname;
        (void)len;
        return 0;
    }


    int CyaSSL_RAND_write_file(const char* fname)
    {
        (void)fname;
        return 0;
    }


    int CyaSSL_RAND_load_file(const char* fname, long len)
    {
        (void)fname;
        /* CTaoCrypt provides enough entropy internally or will report error */
        if (len == -1)
            return 1024;
        else
            return (int)len;
    }


    int CyaSSL_RAND_egd(const char* path)
    {
        (void)path;
        return 0;
    }



    CYASSL_COMP_METHOD* CyaSSL_COMP_zlib(void)
    {
        return 0;
    }


    CYASSL_COMP_METHOD* CyaSSL_COMP_rle(void)
    {
        return 0;
    }


    int CyaSSL_COMP_add_compression_method(int method, void* data)
    {
        (void)method;
        (void)data;
        return 0;
    }



    int CyaSSL_get_ex_new_index(long idx, void* data, void* cb1, void* cb2,
                             void* cb3)
    {
        (void)idx;
        (void)data;
        (void)cb1;
        (void)cb2;
        (void)cb3;
        return 0;
    }


    void CyaSSL_set_dynlock_create_callback(CYASSL_dynlock_value* (*f)(
                                                              const char*, int))
    {
        (void)f;
    }


    void CyaSSL_set_dynlock_lock_callback(
                 void (*f)(int, CYASSL_dynlock_value*, const char*, int))
    {
        (void)f;
    }


    void CyaSSL_set_dynlock_destroy_callback(
                      void (*f)(CYASSL_dynlock_value*, const char*, int))
    {
        (void)f;
    }



    const char* CyaSSL_X509_verify_cert_error_string(long err)
    {
        (void)err;
        return 0;
    }



    int CyaSSL_X509_LOOKUP_add_dir(CYASSL_X509_LOOKUP* lookup, const char* dir,
                                   long len)
    {
        (void)lookup;
        (void)dir;
        (void)len;
        return 0;
    }


    int CyaSSL_X509_LOOKUP_load_file(CYASSL_X509_LOOKUP* lookup,
                                     const char* file, long len)
    {
        (void)lookup;
        (void)file;
        (void)len;
        return 0;
    }


    CYASSL_X509_LOOKUP_METHOD* CyaSSL_X509_LOOKUP_hash_dir(void)
    {
        return 0;
    }


    CYASSL_X509_LOOKUP_METHOD* CyaSSL_X509_LOOKUP_file(void)
    {
        return 0;
    }



    CYASSL_X509_LOOKUP* CyaSSL_X509_STORE_add_lookup(CYASSL_X509_STORE* store,
                                                   CYASSL_X509_LOOKUP_METHOD* m)
    {
        (void)store;
        (void)m;
        return 0;
    }


    CYASSL_X509_STORE* CyaSSL_X509_STORE_new(void)
    {
        return 0;
    }


    int CyaSSL_X509_STORE_get_by_subject(CYASSL_X509_STORE_CTX* ctx, int idx,
                                CYASSL_X509_NAME* name, CYASSL_X509_OBJECT* obj)
    {
        (void)ctx;
        (void)idx;
        (void)name;
        (void)obj;
        return 0;
    }


    int CyaSSL_X509_STORE_CTX_init(CYASSL_X509_STORE_CTX* ctx,
         CYASSL_X509_STORE* store, CYASSL_X509* x509, STACK_OF(CYASSL_X509)* sk)
    {
        (void)ctx;
        (void)store;
        (void)x509;
        (void)sk;
        return 0;
    }


    void CyaSSL_X509_STORE_CTX_cleanup(CYASSL_X509_STORE_CTX* ctx)
    {
        (void)ctx;
    }



    CYASSL_ASN1_TIME* CyaSSL_X509_CRL_get_lastUpdate(CYASSL_X509_CRL* crl)
    {
        (void)crl;
        return 0;
    }


    CYASSL_ASN1_TIME* CyaSSL_X509_CRL_get_nextUpdate(CYASSL_X509_CRL* crl)
    {
        (void)crl;
        return 0;
    }



    CYASSL_EVP_PKEY* CyaSSL_X509_get_pubkey(CYASSL_X509* x509)
    {
        (void)x509;
        return 0;
    }


    int CyaSSL_X509_CRL_verify(CYASSL_X509_CRL* crl, CYASSL_EVP_PKEY* key)
    {
        (void)crl;
        (void)key;
        return 0;
    }


    void CyaSSL_X509_STORE_CTX_set_error(CYASSL_X509_STORE_CTX* ctx, int err)
    {
        (void)ctx;
        (void)err;
    }


    void CyaSSL_X509_OBJECT_free_contents(CYASSL_X509_OBJECT* obj)
    {
        (void)obj;
    }


    void CyaSSL_EVP_PKEY_free(CYASSL_EVP_PKEY* key)
    {
        (void)key;
    }


    int CyaSSL_X509_cmp_current_time(const CYASSL_ASN1_TIME* asnTime)
    {
        (void)asnTime;
        return 0;
    }


    int CyaSSL_sk_X509_REVOKED_num(CYASSL_X509_REVOKED* revoked)
    {
        (void)revoked;
        return 0;
    }



    CYASSL_X509_REVOKED* CyaSSL_X509_CRL_get_REVOKED(CYASSL_X509_CRL* crl)
    {
        (void)crl;
        return 0;
    }


    CYASSL_X509_REVOKED* CyaSSL_sk_X509_REVOKED_value(
                                        CYASSL_X509_REVOKED* revoked, int value)
    {
        (void)revoked;
        (void)value;
        return 0;
    }



    CYASSL_ASN1_INTEGER* CyaSSL_X509_get_serialNumber(CYASSL_X509* x509)
    {
        (void)x509;
        return 0;
    }


    int CyaSSL_ASN1_TIME_print(CYASSL_BIO* bio, const CYASSL_ASN1_TIME* asnTime)
    {
        (void)bio;
        (void)asnTime;
        return 0;
    }



    int CyaSSL_ASN1_INTEGER_cmp(const CYASSL_ASN1_INTEGER* a,
                                const CYASSL_ASN1_INTEGER* b)
    {
        (void)a;
        (void)b;
        return 0;
    }


    long CyaSSL_ASN1_INTEGER_get(const CYASSL_ASN1_INTEGER* i)
    {
        (void)i;
        return 0;
    }



    void* CyaSSL_X509_STORE_CTX_get_ex_data(CYASSL_X509_STORE_CTX* ctx, int idx)
    {
        (void)ctx;
        (void)idx;
        return 0;
    }


    int CyaSSL_get_ex_data_X509_STORE_CTX_idx(void)
    {
        return 0;
    }


    void* CyaSSL_get_ex_data(const CYASSL* ssl, int idx)
    {
        (void)ssl;
        (void)idx;
        return 0;
    }


    long CyaSSL_CTX_set_timeout(CYASSL_CTX* ctx, long to)
    {
        (void)ctx;
        (void)to;
        return 0;
    }


    void CyaSSL_CTX_set_info_callback(CYASSL_CTX* ctx, void (*f)(void))
    {
        (void)ctx;
        (void)f;
    }


    unsigned long CyaSSL_ERR_peek_error(void)
    {
        return 0;
    }


    int CyaSSL_ERR_GET_REASON(int err)
    {
        (void)err;
        return 0;
    }


    char* CyaSSL_alert_type_string_long(int alertID)
    {
        (void)alertID;
        return 0;
    }


    char* CyaSSL_alert_desc_string_long(int alertID)
    {
        (void)alertID;
        return 0;
    }


    char* CyaSSL_state_string_long(CYASSL* ssl)
    {
        (void)ssl;
        return 0;
    }



    void CyaSSL_RSA_free(CYASSL_RSA* rsa)
    {
        (void)rsa;
    }


    int CyaSSL_PEM_def_callback(char* name, int num, int w, void* key)
    {
        (void)name;
        (void)num;
        (void)w;
        (void)key;
        return 0;
    }
    

    long CyaSSL_CTX_sess_accept(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_connect(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_accept_good(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_connect_good(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_accept_renegotiate(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_connect_renegotiate(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_hits(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_cb_hits(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_cache_full(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_misses(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_timeouts(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    long CyaSSL_CTX_sess_number(CYASSL_CTX* ctx)
    {
        (void)ctx;
        return 0;
    }


    void CyaSSL_DES_set_key_unchecked(CYASSL_const_DES_cblock* myDes,
                                                   CYASSL_DES_key_schedule* key)
    {
        (void)myDes;
        (void)key;
    }


    void CyaSSL_DES_set_odd_parity(CYASSL_DES_cblock* myDes)
    {
        (void)myDes;
    }

    
    void CyaSSL_DES_ecb_encrypt(CYASSL_DES_cblock* desa,
                 CYASSL_DES_cblock* desb, CYASSL_DES_key_schedule* key, int len)
    {
        (void)desa;
        (void)desb;
        (void)key;
        (void)len;
    }

    int CyaSSL_BIO_printf(CYASSL_BIO* bio, const char* format, ...)
    {
        (void)bio;
        (void)format;
        return 0;
    }


    int CyaSSL_ASN1_UTCTIME_print(CYASSL_BIO* bio, const CYASSL_ASN1_UTCTIME* a)
    {
        (void)bio;
        (void)a;
        return 0;
    }
    

    int  CyaSSL_sk_num(CYASSL_X509_REVOKED* rev)
    {
        (void)rev;
        return 0;
    }


    void* CyaSSL_sk_value(CYASSL_X509_REVOKED* rev, int i)
    {
        (void)rev;
        (void)i;
        return 0;
    }


    /* stunnel 4.28 needs */
    void* CyaSSL_CTX_get_ex_data(const CYASSL_CTX* ctx, int d)
    {
        (void)ctx;
        (void)d;
        return 0;
    }


    int CyaSSL_CTX_set_ex_data(CYASSL_CTX* ctx, int d, void* p)
    {
        (void)ctx;
        (void)d;
        (void)p;
        return SSL_SUCCESS;
    }


    void CyaSSL_CTX_sess_set_get_cb(CYASSL_CTX* ctx,
                        CYASSL_SESSION*(*f)(CYASSL*, unsigned char*, int, int*))
    {
        (void)ctx;
        (void)f;
    }


    void CyaSSL_CTX_sess_set_new_cb(CYASSL_CTX* ctx,
                                 int (*f)(CYASSL*, CYASSL_SESSION*))
    {
        (void)ctx;
        (void)f;
    }


    void CyaSSL_CTX_sess_set_remove_cb(CYASSL_CTX* ctx, void (*f)(CYASSL_CTX*,
                                                            CYASSL_SESSION*))
    {
        (void)ctx;
        (void)f;
    }


    int CyaSSL_i2d_SSL_SESSION(CYASSL_SESSION* sess, unsigned char** p)
    {
        (void)sess;
        (void)p;
        return sizeof(CYASSL_SESSION);
    }


    CYASSL_SESSION* CyaSSL_d2i_SSL_SESSION(CYASSL_SESSION** sess,
                                    const unsigned char** p, long i)
    {
        (void)p;
        (void)i;
        if (sess)
            return *sess;
        return NULL;
    }


    long CyaSSL_SESSION_get_timeout(const CYASSL_SESSION* sess)
    {
        CYASSL_ENTER("CyaSSL_SESSION_get_timeout");
        return sess->timeout;
    }


    long CyaSSL_SESSION_get_time(const CYASSL_SESSION* sess)
    {
        CYASSL_ENTER("CyaSSL_SESSION_get_time");
        return sess->bornOn;
    }


    int CyaSSL_CTX_get_ex_new_index(long idx, void* arg, void* a, void* b,
                                    void* c)
    {
        (void)idx;
        (void)arg;
        (void)a;
        (void)b;
        (void)c;
        return 0; 
    }

    /* write X509 serial number in unsigned binary to buffer 
       buffer needs to be at least EXTERNAL_SERIAL_SIZE (32) for all cases
       return 0 on success */
    int CyaSSL_X509_get_serial_number(CYASSL_X509* x509, byte* in, int* inOutSz)
    {
        CYASSL_ENTER("CyaSSL_X509_get_serial_number");
        if (x509 == NULL || in == NULL || *inOutSz < x509->serialSz)
            return BAD_FUNC_ARG;

        XMEMCPY(in, x509->serial, x509->serialSz);
        *inOutSz = x509->serialSz;

        return 0;
    }

    char*  CyaSSL_X509_get_subjectCN(CYASSL_X509* x509)
    {
        if (x509 == NULL)
            return NULL;

        return x509->subjectCN;
    }

#endif /* OPENSSL_EXTRA */


#ifdef SESSION_CERTS


/* Get peer's certificate chain */
CYASSL_X509_CHAIN* CyaSSL_get_peer_chain(CYASSL* ssl)
{
    CYASSL_ENTER("CyaSSL_get_peer_chain");
    if (ssl)
        return &ssl->session.chain;

    return 0;
}


/* Get peer's certificate chain total count */
int CyaSSL_get_chain_count(CYASSL_X509_CHAIN* chain)
{
    CYASSL_ENTER("CyaSSL_get_chain_count");
    if (chain)
        return chain->count;

    return 0;
}


/* Get peer's ASN.1 DER ceritifcate at index (idx) length in bytes */
int CyaSSL_get_chain_length(CYASSL_X509_CHAIN* chain, int idx)
{
    CYASSL_ENTER("CyaSSL_get_chain_length");
    if (chain)
        return chain->certs[idx].length;

    return 0;
}


/* Get peer's ASN.1 DER ceritifcate at index (idx) */
byte* CyaSSL_get_chain_cert(CYASSL_X509_CHAIN* chain, int idx)
{
    CYASSL_ENTER("CyaSSL_get_chain_cert");
    if (chain)
        return chain->certs[idx].buffer;

    return 0;
}


/* Get peer's PEM ceritifcate at index (idx), output to buffer if inLen big
   enough else return error (-1), output length is in *outLen */
int  CyaSSL_get_chain_cert_pem(CYASSL_X509_CHAIN* chain, int idx,
                               unsigned char* buf, int inLen, int* outLen)
{
    const char header[] = "-----BEGIN CERTIFICATE-----\n";
    const char footer[] = "-----END CERTIFICATE-----\n";

    int headerLen = sizeof(header) - 1;
    int footerLen = sizeof(footer) - 1;
    int i;
    int err;

    CYASSL_ENTER("CyaSSL_get_chain_cert_pem");
    if (!chain || !outLen || !buf)
        return BAD_FUNC_ARG;

    /* don't even try if inLen too short */
    if (inLen < headerLen + footerLen + chain->certs[idx].length)
        return BAD_FUNC_ARG;

    /* header */
    XMEMCPY(buf, header, headerLen);
    i = headerLen;

    /* body */
    *outLen = inLen;  /* input to Base64_Encode */
    if ( (err = Base64_Encode(chain->certs[idx].buffer,
                       chain->certs[idx].length, buf + i, (word32*)outLen)) < 0)
        return err;
    i += *outLen;

    /* footer */
    if ( (i + footerLen) > inLen)
        return BAD_FUNC_ARG;
    XMEMCPY(buf + i, footer, footerLen);
    *outLen += headerLen + footerLen; 

    return 0;
}


/* get session ID */
const byte* CyaSSL_get_sessionID(const CYASSL_SESSION* session)
{
    CYASSL_ENTER("CyaSSL_get_sessionID");
    return session->sessionID;
}


/* connect enough to get peer cert chain */
int CyaSSL_connect_cert(CYASSL* ssl)
{
    int  ret;

    if (ssl == NULL)
        return SSL_FAILURE;

    ssl->options.certOnly = 1;
    ret = CyaSSL_connect(ssl);
    ssl->options.certOnly   = 0;

    return ret;
}

#endif /* SESSION_CERTS */

