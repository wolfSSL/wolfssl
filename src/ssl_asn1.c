/* ssl_asn1.c
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

#include <wolfssl/internal.h>
#ifndef WC_NO_RNG
    #include <wolfssl/wolfcrypt/random.h>
#endif

#if !defined(WOLFSSL_SSL_ASN1_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_asn1.c does not need to be compiled separately from ssl.c
    #endif
#else

/*******************************************************************************
 * ASN1_item APIs
 ******************************************************************************/

#ifndef OPENSSL_EXTRA_NO_ASN1

#ifndef NO_ASN

#ifdef OPENSSL_EXTRA

#ifdef OPENSSL_ALL

/* Provides access to the member of the obj offset by offset */
#define asn1Mem(obj, offset) (*(void**)(((byte*)(obj)) + (offset)))
#define asn1Type(obj, offset) (*(int*)(((byte*)(obj)) + (offset)))

static void* asn1_new_tpl(const WOLFSSL_ASN1_TEMPLATE *mem)
{
    if (mem->sequence)
        return wolfSSL_sk_new_null();
    else
        return mem->new_func();
}

static void* asn1_item_alloc(const WOLFSSL_ASN1_ITEM* item)
{
    void* ret = NULL;

    /* allocation */
    switch (item->type) {
        case WOLFSSL_ASN1_SEQUENCE:
        case WOLFSSL_ASN1_CHOICE:
            ret = (void *)XMALLOC(item->size, NULL, DYNAMIC_TYPE_OPENSSL);
            if (ret != NULL)
                XMEMSET(ret, 0, item->size);
            break;
        case WOLFSSL_ASN1_OBJECT_TYPE:
            if (item->mcount != 1 || item->members->offset) {
                WOLFSSL_MSG("incorrect member count or offset");
                return NULL;
            }
            ret = asn1_new_tpl(item->members);
            break;
        default:
            WOLFSSL_MSG("ASN1 type not implemented");
            return NULL;
    }

    return ret;
}

static int asn1_item_init(void* obj, const WOLFSSL_ASN1_ITEM* item)
{
    const WOLFSSL_ASN1_TEMPLATE *mem = NULL;
    size_t i;
    int ret = 0;

    switch (item->type) {
        case WOLFSSL_ASN1_SEQUENCE:
            for (mem = item->members, i = 0; i < item->mcount; mem++, i++) {
                asn1Mem(obj, mem->offset) = asn1_new_tpl(mem);
                if (asn1Mem(obj, mem->offset) == NULL) {
                    ret = WOLFSSL_FATAL_ERROR;
                    break;
                }
            }
            break;
        case WOLFSSL_ASN1_OBJECT_TYPE:
            /* Initialized by new_func. Nothing to do. */
            break;
        case WOLFSSL_ASN1_CHOICE:
            asn1Type(obj, item->toffset) = -1;
            /* We don't know what to initialize. Nothing to do. */
            break;
        default:
            WOLFSSL_MSG("ASN1 type not implemented");
            ret = WOLFSSL_FATAL_ERROR;
            break;
    }

    return ret;
}

/* Create a new ASN1 item based on a template.
 *
 * @param [in] item  Info about ASN1 items.
 * @return  A new ASN1 item on success.
 * @return  NULL when item is NULL, dynamic memory allocation fails or ASN1
 *          item type not supported.
 */
void* wolfSSL_ASN1_item_new(const WOLFSSL_ASN1_ITEM* item)
{
    void* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_item_new");

    if (item == NULL)
        return NULL;

    /* allocation */
    ret = asn1_item_alloc(item);
    if (ret == NULL)
        return NULL;

    /* initialization */
    if (asn1_item_init(ret, item) != 0) {
        wolfSSL_ASN1_item_free(ret, item);
        ret = NULL;
    }

    return ret;
}

static void asn1_free_tpl(void *obj, const WOLFSSL_ASN1_TEMPLATE *mem)
{
    if (obj != NULL) {
        if (mem->sequence)
            wolfSSL_sk_pop_free((WOLFSSL_STACK *)obj, mem->free_func);
        else
            mem->free_func(obj);
    }
}

/* Dispose of ASN1 item based on a template.
 *
 * @param [in, out] val  ASN item to free.
 * @param [in,      item Info about ASN1 items.
 */
void wolfSSL_ASN1_item_free(void *obj, const WOLFSSL_ASN1_ITEM *item)
{
    const WOLFSSL_ASN1_TEMPLATE *mem = NULL;
    size_t i;

    WOLFSSL_ENTER("wolfSSL_ASN1_item_free");

    if (obj != NULL) {
        switch (item->type) {
            case WOLFSSL_ASN1_SEQUENCE:
                for (mem = item->members, i = 0; i < item->mcount; mem++, i++)
                    asn1_free_tpl(asn1Mem(obj, mem->offset), mem);
                XFREE(obj, NULL, DYNAMIC_TYPE_OPENSSL);
                break;
            case WOLFSSL_ASN1_CHOICE:
                if (asn1Type(obj, item->toffset) < 0)
                    break; /* type not set */
                for (mem = item->members, i = 0; i < item->mcount; mem++, i++) {
                    if (asn1Type(obj, item->toffset) == mem->tag) {
                        asn1_free_tpl(asn1Mem(obj, mem->offset), mem);
                        break;
                    }
                }
                XFREE(obj, NULL, DYNAMIC_TYPE_OPENSSL);
                break;
            case WOLFSSL_ASN1_OBJECT_TYPE:
                asn1_free_tpl(obj, item->members);
                break;
            default:
                WOLFSSL_MSG("ASN1 type not implemented");
                break;
        }
    }
}

static int i2d_asn1_items(const void* obj, byte** buf,
        const WOLFSSL_ASN1_TEMPLATE* mem)
{
    int len = 0;
    int ret = 0;
    if (mem->sequence) {
        const WOLFSSL_STACK* sk = (WOLFSSL_STACK *)asn1Mem(obj, mem->offset);
        int ski; /* stack index */
        int innerLen = 0;
        /* Figure out the inner length first */
        for (ski = 0; ski < wolfSSL_sk_num(sk); ski++) {
            ret = mem->i2d_func(wolfSSL_sk_value(sk, ski), NULL);
            if (ret <= 0)
                break;
            innerLen += ret;
        }
        if (ret <= 0)
            return 0;
        if (buf != NULL && *buf != NULL) {
            /* Now write it out */
            int writeLen = 0;
            *buf += SetSequence((word32)innerLen, *buf);
            for (ski = 0; ski < wolfSSL_sk_num(sk); ski++) {
                ret = mem->i2d_func(wolfSSL_sk_value(sk, ski), buf);
                if (ret <= 0)
                    break;
                writeLen += ret;
            }
            if (ret <= 0 || writeLen != innerLen)
                return 0;
        }
        len = (int)SetSequence((word32)innerLen, NULL) + innerLen;
    }
    else {
        ret = mem->i2d_func(asn1Mem(obj, mem->offset),
                buf != NULL && *buf != NULL ? buf : NULL);
        if (ret <= 0)
            return 0;
        len = ret;
    }
    return len;
}

/* Encode members of an ASN.1 SEQUENCE as DER.
 *
 * @param [in]      src      ASN1 items to encode.
 * @param [in, out] buf      Buffer to encode into. May be NULL.
 * @param [in]      members  ASN1 template members.
 * @param [in]      mcount   Count of template members.
 * @return  Length of DER encoding on success.
 * @return  0 on failure.
 */
static int wolfssl_i2d_asn1_items(const void* obj, byte* buf,
    const WOLFSSL_ASN1_TEMPLATE* members, size_t mcount)
{
    const WOLFSSL_ASN1_TEMPLATE* mem = NULL;
    int len = 0;
    int ret;
    size_t i;

    WOLFSSL_ENTER("wolfssl_i2d_asn1_items");

    for (mem = members, i = 0; i < mcount; mem++, i++) {
        byte* tmp = buf;
        if (mem->ex && mem->tag >= 0) {
            /* Figure out the inner length */
            int innerLen = 0;
            int hdrLen = 0;
            ret = i2d_asn1_items(obj, NULL, mem);
            if (ret <= 0) {
                len = 0;
                break;
            }
            innerLen = ret;
            hdrLen = SetExplicit((byte)mem->tag, (word32)innerLen, buf, 0);
            len += hdrLen;
            if (buf != NULL)
                buf += hdrLen;
        }

        ret = i2d_asn1_items(obj, &buf, mem);
        if (ret <= 0) {
            len = 0;
            break;
        }

        if (buf != NULL && tmp != NULL && !mem->ex && mem->tag >= 0) {
            byte imp[ASN_TAG_SZ + MAX_LENGTH_SZ];
            /* Encode the implicit tag; There's other stuff in the upper bits
             * of the integer tag, so strip out everything else for value. */
            SetImplicit(tmp[0], (byte)(mem->tag), 0, imp, 0);
            tmp[0] = imp[0];
        }
        len += ret;
    }

    WOLFSSL_LEAVE("wolfssl_i2d_asn1_items", len);

    return len;
}

/* Encode sequence and items under it.
 *
 * @param [in]      src  ASN1 items to encode.
 * @param [in, out] buf  Buffer to encode into. May be NULL.
 * @param [in]      tpl  Template of ASN1 items.
 * @return  Length of DER encoding on success.
 * @return  0 on failure.
 */
static int i2d_ASN_SEQUENCE(const void* obj, byte* buf,
    const WOLFSSL_ASN1_ITEM* item)
{
    word32 seq_len;
    word32 len = 0;

    seq_len = (word32)wolfssl_i2d_asn1_items(obj, NULL, item->members,
        item->mcount);
    if (seq_len != 0) {
        len = SetSequence(seq_len, buf);
        if (buf != NULL) {
            if (wolfssl_i2d_asn1_items(obj, buf + len, item->members,
                    item->mcount) > 0)
                len += seq_len; /* success */
            else
                len = 0; /* error */
        }
        else
            len += seq_len;
    }

    return (int)len;
}

static int i2d_ASN_CHOICE(const void* obj, byte* buf,
        const WOLFSSL_ASN1_ITEM* item)
{
    const WOLFSSL_ASN1_TEMPLATE* mem = NULL;
    size_t i;

    if (asn1Type(obj, item->toffset) < 0)
        return 0; /* type not set */
    for (mem = item->members, i = 0; i < item->mcount; mem++, i++) {
        if (asn1Type(obj, item->toffset) == mem->tag) {
            return wolfssl_i2d_asn1_items(obj, buf, mem, 1);
        }
    }
    return 0;
}

static int i2d_ASN_OBJECT_TYPE(const void* obj, byte* buf,
        const WOLFSSL_ASN1_ITEM* item)
{
    /* To be able to use wolfssl_i2d_asn1_items without any modifications,
     * pass in a pointer to obj so that asn1Mem uses the correct pointer. */
    const void ** obj_pp = &obj;
    return wolfssl_i2d_asn1_items(obj_pp, buf, item->members, item->mcount);
}

/* Encode ASN1 template item.
 *
 * @param [in]      src  ASN1 items to encode.
 * @param [in, out] buf  Buffer to encode into. May be NULL.
 * @param [in]      tpl  Template of ASN1 items.
 * @return  Length of DER encoding on success.
 * @return  0 on failure.
 */
static int wolfssl_asn1_item_encode(const void* obj, byte* buf,
    const WOLFSSL_ASN1_ITEM* item)
{
    int len;

    switch (item->type) {
        case WOLFSSL_ASN1_SEQUENCE:
            len = i2d_ASN_SEQUENCE(obj, buf, item);
            break;
        case WOLFSSL_ASN1_OBJECT_TYPE:
            len = i2d_ASN_OBJECT_TYPE(obj, buf, item);
            break;
        case WOLFSSL_ASN1_CHOICE:
            len = i2d_ASN_CHOICE(obj, buf, item);
            break;
        default:
            WOLFSSL_MSG("Type not supported in wolfSSL_ASN1_item_i2d");
            len = 0;
    }

    return len;
}

/* Encode ASN1 template.
 *
 * @param [in]      src   ASN1 items to encode.
 * @param [in, out] dest  Pointer to buffer to encode into. May be NULL.
 * @param [in]      tpl   Template of ASN1 items.
 * @return  Length of DER encoding on success.
 * @return  WOLFSSL_FATAL_ERROR on failure.
 */
int wolfSSL_ASN1_item_i2d(const void* obj, byte** dest,
    const WOLFSSL_ASN1_ITEM* item)
{
    int ret = 1;
    int len = 0;

    WOLFSSL_ENTER("wolfSSL_ASN1_item_i2d");

    /* Validate parameters. */
    if ((obj == NULL) || (item == NULL)) {
        ret = 0;
    }

    if ((ret == 1) && ((len = wolfssl_asn1_item_encode(obj, NULL, item)) == 0))
        ret = 0;

    if ((ret == 1) && (dest != NULL)) {
        byte* buf = NULL;
        if (*dest == NULL) {
            buf = (byte*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_ASN1);
            if (buf == NULL)
                ret = 0;
        }
        else
            buf = *dest;

        if (ret == 1) {
            len = wolfssl_asn1_item_encode(obj, buf, item);
            if (len <= 0)
                ret = 0;
        }

        if (ret == 1) {
            if (*dest == NULL)
                *dest = buf;
            else
                *dest += len;
        }
        if (ret == 0 && *dest == NULL)
            XFREE(buf, NULL, DYNAMIC_TYPE_ASN1);
    }

    if (ret == 0) {
        len = WOLFSSL_FATAL_ERROR;
    }
    WOLFSSL_LEAVE("wolfSSL_ASN1_item_i2d", len);
    return len;
}

static void* d2i_obj(const WOLFSSL_ASN1_TEMPLATE* mem, const byte** src,
        long* len)
{
    void* ret;
    const byte* tmp = *src;
    ret = mem->d2i_func(NULL, &tmp, *len);
    if (ret == NULL) {
        WOLFSSL_MSG("d2i error");
        return NULL;
    }
    if (tmp <= *src) {
        WOLFSSL_MSG("ptr not advanced");
        mem->free_func(ret); /* never a stack so we can call this directly */
        return NULL;
    }
    *len -= (long)(tmp - *src);
    *src = tmp;
    return ret;
}

static void* d2i_generic_obj(const WOLFSSL_ASN1_TEMPLATE* mem, const byte** src,
        long* len)
{
    void* ret = NULL;
    if (mem->sequence) {
        long skl = 0;
        int slen = 0;
        WOLFSSL_STACK* sk = NULL;
        word32 idx = 0;
        const byte* tmp = *src;
        if (GetSequence(tmp, &idx, &slen, (word32)*len) < 0)
            goto error;
        skl = (long)slen;
        tmp += idx;
        ret = sk = wolfSSL_sk_new_null();
        while (skl > 0) {
            void* new_obj = d2i_obj(mem, &tmp, &skl);
            if (new_obj == NULL) {
                WOLFSSL_MSG("d2i_obj failed");
                goto error;
            }
            if (wolfSSL_sk_insert(sk, new_obj, -1) <= 0) {
                mem->free_func(new_obj);
                WOLFSSL_MSG("push failed");
                goto error;
            }
        }
        if (skl != 0) {
            WOLFSSL_MSG("l not zero after sequence");
            goto error;
        }
        *len -= (long)slen;
        *src = tmp;
    }
    else {
        ret = d2i_obj(mem, src, len);
    }
    return ret;
error:
    asn1_free_tpl(ret, mem);
    return NULL;
}

static int d2i_handle_tags(const WOLFSSL_ASN1_TEMPLATE* mem, const byte** src,
        long* len, byte** impBuf, int* asnLen)
{
    if (mem->tag >= 0) {
        byte tag = 0;
        word32 idx = 0;
        if (mem->ex) {
            if (GetASNTag(*src, &idx, &tag, (word32)*len) < 0 ||
                    (byte)(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | mem->tag)
                        != tag ||
                    GetLength(*src, &idx, asnLen, (word32)*len) < 0) {
                WOLFSSL_MSG("asn tag error");
                return WOLFSSL_FATAL_ERROR;
            }
            *len -= idx;
            *src += idx;
        }
        else {
            /* Underlying d2i functions won't be able to handle the implicit
             * tag so we substitute it for the expected tag. */
            if (mem->first_byte == 0) {
                WOLFSSL_MSG("first byte not set");
                return WOLFSSL_FATAL_ERROR;
            }
            if (GetASNTag(*src, &idx, &tag, (word32)*len) < 0 ||
                    (byte)mem->tag != (tag & ASN_TYPE_MASK) ||
                    GetLength(*src, &idx, asnLen, (word32)*len) < 0) {
                WOLFSSL_MSG("asn tag error");
                return WOLFSSL_FATAL_ERROR;
            }
            *asnLen += idx; /* total buffer length */
            *impBuf = (byte*)XMALLOC(*asnLen, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
            if (*impBuf == NULL) {
                WOLFSSL_MSG("malloc error");
                return WOLFSSL_FATAL_ERROR;
            }
            XMEMCPY(*impBuf, *src, *asnLen);
            (*impBuf)[0] = mem->first_byte;
        }
    }
    return 0;
}

static void* d2i_generic(const WOLFSSL_ASN1_TEMPLATE* mem,
        const byte** src, long* len)
{
    int asnLen = -1;
    const byte *tmp = NULL;
    void* ret = NULL;
    byte* impBuf = NULL;
    long l;

    if (*len <= 0) {
        WOLFSSL_MSG("buffer too short");
        return NULL;
    }

    if (d2i_handle_tags(mem, src, len, &impBuf, &asnLen) != 0) {
        WOLFSSL_MSG("tags error");
        goto error;
    }

    if (impBuf != NULL)
        tmp = impBuf;
    else
        tmp = *src;
    l = (long)(asnLen >= 0 ? asnLen : *len);
    ret = d2i_generic_obj(mem, &tmp, &l);
    if (l < 0) {
        WOLFSSL_MSG("ptr advanced too far");
        goto error;
    }
    if (impBuf != NULL) {
        tmp = *src + (tmp - impBuf); /* for the next calculation */
        XFREE(impBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        impBuf = NULL;
    }
    if (asnLen >= 0 && (int)(tmp - *src) != asnLen) {
        WOLFSSL_MSG("ptr not advanced enough");
        goto error;
    }
    *len -= (long)(tmp - *src);
    *src = tmp;
    return ret;
error:
    asn1_free_tpl(ret, mem);
    if (impBuf != NULL)
        XFREE(impBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return NULL;
}

static int d2i_ASN_SEQUENCE(void* obj, const byte **src, long len,
        const WOLFSSL_ASN1_ITEM* item)
{
    const WOLFSSL_ASN1_TEMPLATE* mem = NULL;
    int err;
    word32 idx = 0;
    int slen = 0;
    size_t i;
    const byte* s = *src;

    err = GetSequence(s, &idx, &slen, (word32)len);
    if (err <= 0) {
        WOLFSSL_MSG("GetSequence error");
        return WOLFSSL_FATAL_ERROR;
    }
    s += idx;
    len -= idx;

    for (mem = item->members, i = 0; i < item->mcount; mem++, i++) {
        asn1Mem(obj, mem->offset) = d2i_generic(mem, &s, &len);
        if (asn1Mem(obj, mem->offset) == NULL) {
            WOLFSSL_MSG("d2i error");
            return WOLFSSL_FATAL_ERROR;
        }
    }
    *src = s;
    return 0;
}

static int d2i_ASN_CHOICE(void* obj, const byte **src, long len,
        const WOLFSSL_ASN1_ITEM* item)
{
    const WOLFSSL_ASN1_TEMPLATE* mem = NULL;
    size_t i;

    for (mem = item->members, i = 0; i < item->mcount; mem++, i++) {
        asn1Mem(obj, mem->offset) = d2i_generic(mem, src, &len);
        if (asn1Mem(obj, mem->offset) != NULL) {
            asn1Type(obj, item->toffset) = mem->tag;
            return 0;
        }
    }
    WOLFSSL_MSG("der does not decode with any CHOICE");
    return WOLFSSL_FATAL_ERROR;
}

static void* d2i_ASN_OBJECT_TYPE(const byte **src, long len,
        const WOLFSSL_ASN1_ITEM* item)
{
    return d2i_generic(item->members, src, &len);
}

void* wolfSSL_ASN1_item_d2i(void** dst, const byte **src, long len,
        const WOLFSSL_ASN1_ITEM* item)
{
    void* obj = NULL;
    int err = 0;
    const byte *tmp;

    WOLFSSL_ENTER("wolfSSL_ASN1_item_d2i");

    if (src == NULL || *src == NULL || len <= 0 || item == NULL) {
        WOLFSSL_LEAVE("wolfSSL_ASN1_item_d2i", 0);
        return NULL;
    }

    tmp = *src;

    /* Create an empty object. */

    switch (item->type) {
        case WOLFSSL_ASN1_SEQUENCE:
        case WOLFSSL_ASN1_CHOICE:
            obj = asn1_item_alloc(item);
            if (obj == NULL)
                return NULL;
            break;
        case WOLFSSL_ASN1_OBJECT_TYPE:
            /* allocated later */
            break;
        default:
            WOLFSSL_MSG("Type not supported in wolfSSL_ASN1_item_d2i");
            return NULL;
    }

    switch (item->type) {
        case WOLFSSL_ASN1_SEQUENCE:
            err = d2i_ASN_SEQUENCE(obj, &tmp, len, item);
            break;
        case WOLFSSL_ASN1_CHOICE:
            err = d2i_ASN_CHOICE(obj, &tmp, len, item);
            break;
        case WOLFSSL_ASN1_OBJECT_TYPE:
            obj = d2i_ASN_OBJECT_TYPE(&tmp, len, item);
            if (obj == NULL)
                err = WOLFSSL_FATAL_ERROR;
            break;
        default:
            WOLFSSL_MSG("Type not supported in wolfSSL_ASN1_item_d2i");
            err = WOLFSSL_FATAL_ERROR;
            break;
    }

    if (err == 0)
        *src = tmp;
    else {
        wolfSSL_ASN1_item_free(obj, item);
        obj = NULL;
    }

    if (dst != NULL && obj != NULL) {
        if (*dst != NULL)
            wolfSSL_ASN1_item_free(*dst, item);
        *dst = obj;
    }

    WOLFSSL_LEAVE("wolfSSL_ASN1_item_d2i", obj != NULL);
    return obj;
}

#endif /* OPENSSL_ALL */

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * ASN1_BIT_STRING APIs
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(WOLFSSL_WPAS_SMALL)
/* Create a new ASN.1 BIT_STRING object.
 *
 * @return  ASN.1 BIT_STRING object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_BIT_STRING* wolfSSL_ASN1_BIT_STRING_new(void)
{
    WOLFSSL_ASN1_BIT_STRING* bitStr;

    bitStr = (WOLFSSL_ASN1_BIT_STRING*)XMALLOC(sizeof(WOLFSSL_ASN1_BIT_STRING),
        NULL, DYNAMIC_TYPE_OPENSSL);
    if (bitStr) {
        XMEMSET(bitStr, 0, sizeof(WOLFSSL_ASN1_BIT_STRING));
    }

    return bitStr;
}

/* Dispose of ASN.1 BIT_STRING object.
 *
 * Do not use bitStr after calling this function.
 *
 * @param [in, out] bitStr  ASN.1 BIT_STRING to free. May be NULL.
 */
void wolfSSL_ASN1_BIT_STRING_free(WOLFSSL_ASN1_BIT_STRING* bitStr)
{
    if (bitStr != NULL) {
        /* Dispose of any data allocated in BIT_STRING. */
        XFREE(bitStr->data, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    /* Dispose of the ASN.1 BIT_STRING object. */
    XFREE(bitStr, NULL, DYNAMIC_TYPE_OPENSSL);
}

/* Copy data into an ASN.1 BIT_STRING object.
 *
 * Any existing data is disposed of and a copy of the supplied data is made.
 *
 * @param [in, out] bitStr  ASN.1 BIT_STRING object.
 * @param [in]      data    Data to copy in. May be NULL when len is 0.
 * @param [in]      len     Length of data in bytes.
 * @return  1 on success.
 * @return  0 when bitStr is NULL, len is negative, data is NULL with a
 *          positive length, or dynamic memory allocation fails.
 */
int wolfSSL_ASN1_BIT_STRING_set1(WOLFSSL_ASN1_BIT_STRING* bitStr,
    const unsigned char* data, int len)
{
    byte* tmp = NULL;

    /* Validate parameters. */
    if ((bitStr == NULL) || (len < 0) || ((data == NULL) && (len > 0))) {
        return 0;
    }

    /* Make a copy of the data when there is any. */
    if (len > 0) {
        tmp = (byte*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_OPENSSL);
        if (tmp == NULL) {
            return 0;
        }
        XMEMCPY(tmp, data, (size_t)len);
    }

    /* Dispose of any old data and store the copy. */
    XFREE(bitStr->data, NULL, DYNAMIC_TYPE_OPENSSL);
    bitStr->data = tmp;
    bitStr->length = len;

    return 1;
}

/* Get the value of the bit from the ASN.1 BIT_STRING at specified index.
 *
 * A NULL object a value of 0 for the bit at all indices.
 * A negative index has a value of 0 for the bit.
 *
 * @param [in] bitStr  ASN.1 BIT_STRING object.
 * @param [in] i       Index of bit.
 * @return  Value of bit.
 */
int wolfSSL_ASN1_BIT_STRING_get_bit(const WOLFSSL_ASN1_BIT_STRING* bitStr,
    int i)
{
    int bit = 0;

    /* Check for data and whether index is in range. */
    if ((bitStr != NULL) && (bitStr->data != NULL) && (i >= 0) &&
            (bitStr->length > (i / 8))) {
        bit = (bitStr->data[i / 8] & (1 << (7 - (i % 8)))) ? 1 : 0;
    }

    return bit;
}

/* Grow data to require length.
 *
 * @param [in] bitStr  ASN.1 BIT_STRING object.
 * @param [in] len     Length, in bytes, of data required.
 * @return  1 on success.
 * @return  0 when dynamic memory allocation fails.
 */
static int wolfssl_asn1_bit_string_grow(WOLFSSL_ASN1_BIT_STRING* bitStr,
    int len)
{
    int ret = 1;
    byte* tmp;

#ifdef WOLFSSL_NO_REALLOC
    tmp = (byte*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_OPENSSL);
    if (tmp != NULL && bitStr->data != NULL) {
       XMEMCPY(tmp, bitStr->data, bitStr->length);
       XFREE(bitStr->data, NULL, DYNAMIC_TYPE_OPENSSL);
       bitStr->data = NULL;
    }
#else
    /* Realloc to length required. */
    tmp = (byte*)XREALLOC(bitStr->data, (size_t)len, NULL,
        DYNAMIC_TYPE_OPENSSL);
#endif
    if (tmp == NULL) {
        ret = 0;
    }
    else {
        /* Clear out new, top bytes. */
        if (len > bitStr->length)
            XMEMSET(tmp + bitStr->length, 0, (size_t)(len - bitStr->length));
        bitStr->data = tmp;
        bitStr->length = len;
    }

    return ret;
}

/* Set the value of a bit in the ASN.1 BIT_STRING at specified index.
 *
 * @param [in] bitStr  ASN.1 BIT_STRING object.
 * @param [in] idx     Index of bit to set.
 * @param [in] val     Value of bit to set. Valid values: 0 or 1.
 * @return  1 on success.
 * @return  0 when bitStr is NULL, idx is negative, val is not 0 or 1, or
 *          dynamic memory allocation fails.
 */
int wolfSSL_ASN1_BIT_STRING_set_bit(WOLFSSL_ASN1_BIT_STRING* bitStr, int idx,
    int val)
{
    int ret = 1;
    int i = 0;

    /* Validate parameters. */
    if ((bitStr == NULL) || (idx < 0) || ((val != 0) && (val != 1))) {
        ret = 0;
    }

    if (ret == 1) {
        i = idx / 8;

        /* Check if we need to extend data range. */
        if ((i >= bitStr->length) && (val != 0)) {
            /* Realloc data to handle having bit set at index. */
            ret = wolfssl_asn1_bit_string_grow(bitStr, i + 1);
        }
    }
    if ((ret == 1) && (i < bitStr->length)) {
        /* Bit on at index. */
        byte bit = 1 << (7 - (idx % 8));

        /* Clear bit and set to value. */
        bitStr->data[i] &= ~bit;
        bitStr->data[i] |= bit & (byte)(0 - val);
    }

    return ret;
}

/* Serialize object to DER encoding
 *
 * @param bstr Object to serialize
 * @param pp  Output
 * @return Length on success
 *         Negative number on failure
 */
int wolfSSL_i2d_ASN1_BIT_STRING(const WOLFSSL_ASN1_BIT_STRING* bstr,
        unsigned char** pp)
{
    int len;
    unsigned char* buf;

    if (bstr == NULL || (bstr->data == NULL && bstr->length != 0))
        return WOLFSSL_FATAL_ERROR;

    len = (int)SetBitString((word32)bstr->length, 0, NULL) + bstr->length;
    if (pp != NULL) {
        word32 idx;

        if (*pp != NULL)
            buf = *pp;
        else {
            buf = (byte*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_ASN1);
            if (buf == NULL)
                return WOLFSSL_FATAL_ERROR;
        }

        idx = SetBitString((word32)bstr->length, 0, buf);
        if (bstr->length > 0)
            XMEMCPY(buf + idx, bstr->data, (size_t)bstr->length);

        if (*pp != NULL)
            *pp += len;
        else
            *pp = buf;
    }

    return len;
}

WOLFSSL_ASN1_BIT_STRING* wolfSSL_d2i_ASN1_BIT_STRING(
        WOLFSSL_ASN1_BIT_STRING** out, const byte** src, long len)
{
    WOLFSSL_ASN1_BIT_STRING* ret = NULL;
#ifdef WOLFSSL_ASN_TEMPLATE
    word32 idx = 0;
    byte tag = 0;
    int length = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_ASN1_BIT_STRING");

    if (src == NULL || *src == NULL || len <= 0)
        return NULL;

    if (GetASNTag(*src, &idx, &tag, (word32)len) < 0)
        return NULL;
    if (tag != ASN_BIT_STRING)
        return NULL;
    if (GetLength(*src, &idx, &length, (word32)len) < 0)
        return NULL;
    if (GetASN_BitString(*src, idx, length) != 0)
        return NULL;
    idx++; /* step over unused bits */
    length--;

    ret = wolfSSL_ASN1_BIT_STRING_new();
    if (ret == NULL)
        return NULL;

    if (wolfssl_asn1_bit_string_grow(ret, length) != 1) {
        wolfSSL_ASN1_BIT_STRING_free(ret);
        return NULL;
    }

    XMEMCPY(ret->data, *src + idx, length);
    *src += idx + (word32)length;

    if (out != NULL) {
        if (*out != NULL)
            wolfSSL_ASN1_BIT_STRING_free(*out);
        *out = ret;
    }
#else
    WOLFSSL_MSG("d2i_ASN1_BIT_STRING needs --enable-asn=template");
    (void)out;
    (void)src;
    (void)len;
#endif
    return ret;
}

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

/*******************************************************************************
 * ASN1_INTEGER APIs
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Create a new empty ASN.1 INTEGER object.
 *
 * @return  ASN.1 INTEGER object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_new(void)
{
    WOLFSSL_ASN1_INTEGER* a;

    /* Allocate a new ASN.1 INTEGER object. */
    a = (WOLFSSL_ASN1_INTEGER*)XMALLOC(sizeof(WOLFSSL_ASN1_INTEGER), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (a != NULL) {
        XMEMSET(a, 0, sizeof(WOLFSSL_ASN1_INTEGER));
        /* Use fixed buffer field for data. */
        a->data      = a->intData;
        a->isDynamic = 0;
        /* Maximum supported by fixed buffer. */
        a->dataMax   = WOLFSSL_ASN1_INTEGER_MAX;
        /* No value set - no data. */
        a->length    = 0;
    }

    return a;
}

/* Free the ASN.1 INTEGER object and any dynamically allocated data.
 *
 * @param [in, out] in  ASN.1 INTEGER object.
 */
void wolfSSL_ASN1_INTEGER_free(WOLFSSL_ASN1_INTEGER* in)
{
    if ((in != NULL) && (in->isDynamic)) {
        /* Dispose of any data allocated in INTEGER. */
        XFREE(in->data, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    /* Dispose of the ASN.1 INTEGER object. */
    XFREE(in, NULL, DYNAMIC_TYPE_OPENSSL);
}

/* Get the length of the raw integer value bytes, stripping the DER tag/length
 * header if present. Required for OpenSSL compatibility where ASN1_INTEGER is
 * typedef'd to ASN1_STRING and callers use ASN1_STRING_length() on integers.
 *
 * @param [in] ai  ASN.1 INTEGER object.
 * @return  Length of the raw integer value on success.
 * @return  0 when ai is NULL or data is invalid.
 */
int wolfSSL_ASN1_INTEGER_get_length(const WOLFSSL_ASN1_INTEGER* ai)
{
    if (ai == NULL || ai->data == NULL || ai->length <= 0) {
        return 0;
    }
    if (ai->data[0] == ASN_INTEGER) {
        word32 idx = 1;
        int len = 0;
        if (GetLength(ai->data, &idx, &len, (word32)ai->length) >= 0 &&
                idx + (word32)len == (word32)ai->length) {
            return len;
        }
    }
    /* WOLFSSL_QT / WOLFSSL_HAPROXY format: raw bytes without DER header,
     * or data that coincidentally starts with 0x02 but whose header+value
     * boundaries do not span exactly ai->length. */
    return ai->length;
}

/* Get a pointer to the raw integer value bytes, skipping the DER tag/length
 * header if present. Required for OpenSSL compatibility where ASN1_INTEGER is
 * typedef'd to ASN1_STRING and callers use ASN1_STRING_get0_data() on integers.
 *
 * @param [in] ai  ASN.1 INTEGER object.
 * @return  Pointer to the raw integer value bytes on success.
 * @return  NULL when ai is NULL or data is invalid.
 */
const unsigned char* wolfSSL_ASN1_INTEGER_get0_data(const WOLFSSL_ASN1_INTEGER* ai)
{
    if (ai == NULL || ai->data == NULL || ai->length <= 0) {
        return NULL;
    }
    if (ai->data[0] == ASN_INTEGER) {
        word32 idx = 1;
        int len = 0;
        if (GetLength(ai->data, &idx, &len, (word32)ai->length) >= 0 &&
                idx + (word32)len == (word32)ai->length) {
            return ai->data + idx;
        }
    }
    /* WOLFSSL_QT / WOLFSSL_HAPROXY format: raw bytes without DER header,
     * or data that coincidentally starts with 0x02 but whose header+value
     * boundaries do not span exactly ai->length. */
    return ai->data;
}

#if defined(OPENSSL_EXTRA)
/* Reset the data of ASN.1 INTEGER object back to empty fixed array.
 *
 * @param [in] a  ASN.1 INTEGER object.
 */
static void wolfssl_asn1_integer_reset_data(WOLFSSL_ASN1_INTEGER* a)
{
    /* Don't use dynamic buffer anymore. */
    if (a->isDynamic) {
        /* Cache pointer to allocated data. */
        unsigned char* data = a->data;
        /* No longer dynamic. */
        a->isDynamic = 0;
        /* Point data at fixed array. */
        a->data = a->intData;
        /* Set maximum length to fixed array size. */
        a->dataMax = (unsigned int)sizeof(a->intData);
        /* Dispose of dynamically allocated data. */
        XFREE(data, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    /* Clear out data from fixed array. */
    XMEMSET(a->intData, 0, sizeof(a->intData));
    /* No data, no length. */
    a->length = 0;
    /* No data, not negative. */
    a->negative = 0;
    /* Set type to positive INTEGER. */
    a->type = WOLFSSL_V_ASN1_INTEGER;
}
#endif /* OPENSSL_EXTRA */

/* Setup ASN.1 INTEGER object to handle data of required length.
 *
 * @param [in, out] a    ASN.1 INTEGER object.
 * @param [in]      len  Required length in bytes.
 * @return  1 on success.
 * @return  0 on dynamic memory allocation failure.
 */
static int wolfssl_asn1_integer_require_len(WOLFSSL_ASN1_INTEGER* a, int len,
    int keepOldData)
{
    int ret = 1;
    byte* data;
    byte* oldData = a->intData;

    if (a->isDynamic && (len > (int)a->dataMax)) {
        oldData = a->data;
        a->isDynamic = 0;
        a->data = a->intData;
        a->dataMax = (unsigned int)sizeof(a->intData);
    }
    if ((!a->isDynamic) && (len > (int)a->dataMax)) {
        /* Create a new buffer to hold large integer value. */
        data = (byte*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_OPENSSL);
        if (data == NULL) {
            ret = 0;
        }
        else {
            /* Indicate data is dynamic and copy data over. */
            a->isDynamic = 1;
            a->data = data;
            a->dataMax = (word32)len;
        }
    }
    if (keepOldData) {
         if (oldData != a->data) {
             /* Copy old data into new buffer. */
             XMEMCPY(a->data, oldData, (size_t)a->length);
         }
    } else {
        a->length = 0;
    }
    if (oldData != a->intData) {
         /* Dispose of the old dynamic data. */
         XFREE(oldData, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    return ret;
}

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && \
    defined(WOLFSSL_TSP_VERIFIER)
/* Create an ASN.1 INTEGER object holding a big-endian number in DER form.
 *
 * The data is the ASN.1 type and length followed by the number as supplied.
 *
 * @param [in] val  Big-endian encoding of number.
 * @param [in] len  Length of number in bytes.
 * @return  ASN.1 INTEGER object on success.
 * @return  NULL on failure.
 */
static WOLFSSL_ASN1_INTEGER* wolfssl_asn1_integer_new_buf(
    const unsigned char* val, word32 len)
{
    WOLFSSL_ASN1_INTEGER* a;
    word32 pad;
    word32 hdrSz;
    word32 i = 0;

    /* Defensive: all current callers pass a non-NULL, non-empty magnitude, but
     * this is a shared helper. A NULL val is dereferenced below and a zero
     * length would build a non-canonical empty INTEGER (02 00). */
    if ((val == NULL) || (len == 0))
        return NULL;

    /* Pad with a leading 0x00 when the top bit is set so the DER INTEGER stays
     * positive - the wc layer supplies the magnitude without this pad. */
    pad = (val[0] & 0x80) ? 1 : 0;
    hdrSz = 1 + SetLength(len + pad, NULL);

    a = wolfSSL_ASN1_INTEGER_new();
    if (a == NULL)
        return NULL;

    /* Make sure there is space for the data, pad, ASN.1 type and length. */
    if (wolfssl_asn1_integer_require_len(a, (int)(len + pad + hdrSz), 0) != 1) {
        wolfSSL_ASN1_INTEGER_free(a);
        return NULL;
    }

    a->data[i++] = ASN_INTEGER;
    i += SetLength(len + pad, a->data + i);
    if (pad == 1) {
        a->data[i++] = 0x00;
    }
    XMEMCPY(a->data + i, val, len);
    a->length = (int)(len + i);
    a->type = WOLFSSL_V_ASN1_INTEGER;

    return a;
}
#endif /* OPENSSL_EXTRA && WOLFSSL_TSP && HAVE_PKCS7 && WOLFSSL_TSP_VERIFIER */

/* Duplicate the ASN.1 INTEGER object into a newly allocated one.
 *
 * @param [in] src  ASN.1 INTEGER object to copy.
 * @return  ASN.1 INTEGER object on success.
 * @return  NULL when src is NULL or dynamic memory allocation fails.
 */
WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_dup(const WOLFSSL_ASN1_INTEGER* src)
{
    WOLFSSL_ASN1_INTEGER* dst = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_INTEGER_dup");

    /* Check for object to duplicate. */
    if (src != NULL) {
        /* Create a new ASN.1 INTEGER object to be copied into. */
        dst = wolfSSL_ASN1_INTEGER_new();
    }
    /* Check for object to copy into. */
    if (dst != NULL) {
        /* Copy simple fields. */
        dst->length   = src->length;
        dst->negative = src->negative;
        dst->type     = src->type;

        if (!src->isDynamic) {
            /* Copy over data from/to fixed buffer. */
            XMEMCPY(dst->intData, src->intData, WOLFSSL_ASN1_INTEGER_MAX);
        }
        else if (wolfssl_asn1_integer_require_len(dst, src->length, 0) == 0) {
            wolfSSL_ASN1_INTEGER_free(dst);
            dst = NULL;
        }
        else {
            XMEMCPY(dst->data, src->data, (size_t)src->length);
        }
    }

    return dst;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA)

/* Compare values in two ASN.1 INTEGER objects.
 *
 * @param [in] a  First ASN.1 INTEGER object.
 * @param [in] b  Second ASN.1 INTEGER object.
 * @return Negative value when a is less than b.
 * @return 0 when a equals b.
 * @return Positive value when a is greater than b.
 * @return WOLFSSL_FATAL_ERROR when a or b is NULL.
 */
int wolfSSL_ASN1_INTEGER_cmp(const WOLFSSL_ASN1_INTEGER* a,
    const WOLFSSL_ASN1_INTEGER* b)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_ASN1_INTEGER_cmp");

    /* Validate parameters. */
    if ((a == NULL) || (b == NULL)) {
        WOLFSSL_MSG("Bad parameter.");
        ret = WOLFSSL_FATAL_ERROR;
    }
    /* Negative value < Positive value */
    else if (a->negative && !b->negative) {
        ret = -2; /* avoid collision with WOLFSSL_FATAL_ERROR */
    }
    /* Positive value > Negative value */
    else if (!a->negative && b->negative) {
        ret = 1;
    }
    else {
        /* Check for difference in length. */
        if (a->length != b->length) {
            ret = a->length - b->length;
        }
        else {
            /* Compare data given they are the same length. */
            ret = XMEMCMP(a->data, b->data, (size_t)a->length);
        }
        /* Reverse comparison result when both negative. */
        if (a->negative) {
            ret = -ret;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_ASN1_INTEGER_cmp", ret);

    return ret;
}

/* Calculate 2's complement of DER encoding.
 *
 * @param [in]  data    Array that is number.
 * @param [in]  length  Number of bytes in array.
 * @return  0 on success.
 * @return  -1 when get length from DER header failed.
 */
static void wolfssl_twos_compl(byte* data, int length)
{
    int i;

    /* Invert bits - 1's complement. */
    for (i = 0; i < length; ++i) {
        data[i] = ~data[i];
    }
    /* 2's complement - add 1. */
    for (i = length - 1; (++data[i]) == 0; --i) {
        /* Do nothing. */
    }
}

/* Calculate 2's complement of DER encoding.
 *
 * @param [in|out] data Array that is number.
 * @param [in]  length  Number of bytes in array.
 * @param [out] neg     When NULL, 2's complement data.
 *                      When not NULL, check for negative first and return.
 * @return  0 on success.
 * @return  -1 when get length from DER header failed.
 */
static int wolfssl_asn1_int_twos_compl(byte* data, int length, byte* neg)
{
    int ret = 0;
    word32 idx = 1;     /* Skip tag. */
    int len;

    /* Get length from DER header. */
    if (GetLength(data, &idx, &len, (word32)length) < 0) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        if (neg != NULL) {
            *neg = data[idx] & 0x80;
        }
        if ((neg == NULL) || (*neg != 0)) {
            wolfssl_twos_compl(data + idx, length - (int)idx);
        }
    }

    return ret;
}

/* Encode ASN.1 INTEGER as DER without tag.
 *
 * When out points to NULL, a new buffer is allocated and returned.
 *
 * @param [in]      a    ASN.1 INTEGER object.
 * @param [in, out] out  Pointer to buffer to hold encoding. May point to NULL.
 * @return  Length of encoding on success.
 * @return  -1 when a is NULL or no data, out is NULL, dynamic memory allocation
 *          fails or encoding length fails.
 */
int wolfSSL_i2d_ASN1_INTEGER(const WOLFSSL_ASN1_INTEGER* a, unsigned char** pp)
{
    WOLFSSL_ENTER("wolfSSL_i2d_ASN1_INTEGER");

    /* Validate parameters. */
    if (a == NULL || a->data == NULL || a->length <= 0) {
        WOLFSSL_MSG("Bad parameter.");
        return WOLFSSL_FATAL_ERROR;
    }

    if (pp != NULL) {
        byte* buf;

        if (*pp != NULL)
            buf = *pp;
        else {
            buf = (byte*)XMALLOC((size_t)a->length, NULL, DYNAMIC_TYPE_ASN1);
            if (buf == NULL)
                return WOLFSSL_FATAL_ERROR;
        }

        /* Copy the data (including tag and length) into output buffer. */
        XMEMCPY(buf, a->data, (size_t)a->length);
        /* Only magnitude of the number stored (i.e. the sign isn't encoded).
         * The "negative" field is 1 if the value must be interpreted as
         * negative and we need to output the 2's complement of the value in
         * the DER output.
         */
        if (a->negative &&
                wolfssl_asn1_int_twos_compl(buf, a->length, NULL) != 0) {
            if (*pp == NULL)
                XFREE(buf, NULL, DYNAMIC_TYPE_ASN1);
            return WOLFSSL_FATAL_ERROR;
        }

        if (*pp != NULL)
            *pp += a->length;
        else
            *pp = buf;
    }

    return a->length;
}

/* Decode DER encoding of ASN.1 INTEGER.
 *
 * @param [out]     a     ASN.1 INTEGER object. May be NULL.
 * @param [in, out] in    Pointer to buffer containing DER encoding.
 * @param [in]      inSz  Length of data in buffer.
 * @return  ASN.1 INTEGER object on success.
 * @return  NULL when in or *in is NULL, inSz is less than or equal to 2 or
 *          parsing DER failed.
 */
WOLFSSL_ASN1_INTEGER* wolfSSL_d2i_ASN1_INTEGER(WOLFSSL_ASN1_INTEGER** a,
    const unsigned char** in, long inSz)
{
    WOLFSSL_ASN1_INTEGER* ret = NULL;
    int err = 0;
    word32 idx = 1;
    int len = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_ASN1_INTEGER");

    /* Validate parameters. */
    if ((in == NULL) || (*in == NULL) || (inSz <= 2)) {
        WOLFSSL_MSG("Bad parameter");
        err = 1;
    }

    /* Check that the tag is correct. */
    if ((!err) && (*in)[0] != ASN_INTEGER) {
        WOLFSSL_MSG("Tag doesn't indicate integer type.");
        err = 1;
    }
    /* Check that length and use this instead of inSz. */
    if ((!err) && (GetLength(*in, &idx, &len, (word32)inSz) <= 0)) {
        WOLFSSL_MSG("ASN.1 length not valid.");
        err = 1;
    }
    /* Check that len + idx won't overflow a signed int */
    if ((!err) && (len > INT_MAX - (int)idx)) {
        WOLFSSL_MSG("ASN.1 length too large.");
        err = 1;
    }
    /* Allocate a new ASN.1 INTEGER object. */
    if ((!err) && ((ret = wolfSSL_ASN1_INTEGER_new()) == NULL)) {
        err = 1;
    }
    if ((!err) && (wolfssl_asn1_integer_require_len(ret, (int)idx + len, 0) !=
            1)) {
        err = 1;
    }
    if (!err) {
        /* Set type. */
        ret->type = WOLFSSL_V_ASN1_INTEGER;

        /* Copy DER encoding and length. */
        XMEMCPY(ret->data, *in, (size_t)(idx + (word32)len));
        ret->length = (int)idx + len;
        /* Do 2's complement if number is negative. */
        if (wolfssl_asn1_int_twos_compl(ret->data, ret->length, &ret->negative)
                != 0) {
            err = 1;
        }
    }
    if ((!err) && ret->negative) {
        /* Update type if number was negative. */
        ret->type |= WOLFSSL_V_ASN1_NEG_INTEGER;
    }

    if (err) {
        /* Dispose of dynamically allocated data on error. */
        wolfSSL_ASN1_INTEGER_free(ret);
        ret = NULL;
    }
    else {
        if (a != NULL) {
            /* Return ASN.1 INTEGER through a. */
            *a = ret;
        }
        *in += ret->length;
    }

    return ret;
}

#ifndef NO_BIO

/* Get length of leading hexadecimal characters.
 *
 * Looks for continuation character before carriage returns and line feeds.
 *
 * @param [in]  str   String with input.
 * @param [in]  len   Length of string.
 * @param [out] cont  Line continuation character at end of line before
 *                    carriage returns and line feeds.
 * @return  Number of leading hexadecimal characters in string.
 */
static int wolfssl_a2i_asn1_integer_clear_to_eol(char* str, int len, int* cont)
{
    byte num;
    word32 nLen;
    int i;

    /* Strip off trailing carriage returns and line feeds. */
    while ((len > 0) && ((str[len - 1] == '\n') || (str[len - 1] == '\r'))) {
        len--;
    }
    /* Check for line continuation character. */
    if ((len > 0) && (str[len - 1] == '\\')) {
        *cont = 1;
        len--;
    }
    else {
        *cont = 0;
    }

    /* Find end of hexadecimal characters. */
    nLen = 1;
    for (i = 0; i < len; i++) {
        /* Check if character is a hexadecimal character. */
        if (Base16_Decode((const byte*)str + i, 1, &num, &nLen) ==
            WC_NO_ERR_TRACE(ASN_INPUT_E))
        {
            /* Found end of hexadecimal characters, return count. */
            len = i;
            break;
        }
    }

    return len;
}

/* Read number from BIO as a string.
 *
 * Line continuation character at end of line means next line must be read.
 *
 * @param [in]      bio   BIO to read from.
 * @param [in]      asn1  ASN.1 INTEGER object to put number into.
 * @param [in, out] buf   Buffer to use when reading.
 * @param [in]      size  Length of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_a2i_ASN1_INTEGER(WOLFSSL_BIO *bio, WOLFSSL_ASN1_INTEGER *asn1,
    char *buf, int size)
{
    int ret = 1;
    int readNextLine = 1;
    int len;
    word32 outLen = 0;
    const int hdrSz = 1 + MAX_LENGTH_SZ;

    WOLFSSL_ENTER("wolfSSL_a2i_ASN1_INTEGER");

    if ((bio == NULL) || (asn1 == NULL) || (buf == NULL) || (size <= 0)) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }

    while ((ret == 1) && readNextLine) {
        int lineLen;

        /* Assume we won't be reading any more. */
        readNextLine = 0;

        /* Read a line. */
        lineLen = wolfSSL_BIO_gets(bio, buf, size);
        if (lineLen <= 0) {
            WOLFSSL_MSG("wolfSSL_BIO_gets error");
            ret = 0;
        }

        if (ret == 1) {
            /* Find length of hexadecimal digits in string. */
            lineLen = wolfssl_a2i_asn1_integer_clear_to_eol(buf, lineLen,
                &readNextLine);
            /* Check we have a valid hexadecimal string to process. */
            if ((lineLen == 0) || ((lineLen % 2) != 0)) {
                WOLFSSL_MSG("Invalid line length");
                ret = 0;
            }
        }
        if (ret == 1) {
            /* Calculate length of complete number so far. */
            len = asn1->length + (lineLen / 2);
            /* Make sure enough space for number and maximum header. */
            if (wolfssl_asn1_integer_require_len(asn1, len + hdrSz, outLen != 0)
                    != 1) {
                ret = 0;
            }
        }
        if (ret == 1) {
            /* Decode string and append to data. */
            outLen = (word32)(lineLen / 2);
            (void)Base16_Decode((byte*)buf, (word32)lineLen,
                asn1->data + asn1->length, &outLen);
            /* Update length of data. */
            asn1->length += (int)outLen;
        }
    }

    if (ret == 1) {
        int idx;

        /* Get ASN.1 header length. */
        idx = SetASNInt(asn1->length, asn1->data[0], NULL);
        /* Move data to be after ASN.1 header. */
        XMEMMOVE(asn1->data + idx, asn1->data, (size_t)asn1->length);
        /* Encode ASN.1 header. */
        SetASNInt(asn1->length, asn1->data[idx], asn1->data);
        /* Update length of data. */
        asn1->length += idx;
    }

    return ret;
}

/* Write out number in ASN.1 INTEGER object to BIO as string.
 *
 * @param [in] bp  BIO to write to.
 * @param [in] a   ASN.1 INTEGER object.
 * @return  Number of characters written on success.
 * @return  0 when bp or a is NULL.
 * @return  0 DER header in data is invalid.
 */
int wolfSSL_i2a_ASN1_INTEGER(WOLFSSL_BIO *bp, const WOLFSSL_ASN1_INTEGER *a)
{
    int err = 0;
    word32 idx = 1;     /* Skip ASN.1 INTEGER tag byte. */
    int len = 0;
    byte buf[WOLFSSL_ASN1_INTEGER_MAX * 2 + 1];
    word32 bufLen;

    WOLFSSL_ENTER("wolfSSL_i2a_ASN1_INTEGER");

    /* Validate parameters. */
    if ((bp == NULL) || (a == NULL)) {
         err = 1;
    }

    if (!err) {
        /* Read DER length - must be at least 1 byte. */
        if (GetLength(a->data, &idx, &len, (word32)a->length) <= 0) {
            err = 1;
        }
    }

    /* Keep encoding and writing while no error and bytes in data. */
    while ((!err) && (idx < (word32)a->length)) {
        /* Number of bytes left to encode. */
        int encLen = a->length - (int)idx;
        /* Reduce to maximum buffer size if necessary. */
        if (encLen > (int)sizeof(buf) / 2) {
            encLen = (int)sizeof(buf) / 2;
        }

        /* Encode bytes from data into buffer. */
        bufLen = (int)sizeof(buf);
        (void)Base16_Encode(a->data + idx, (word32)encLen, buf, &bufLen);
        /* Update index to next bytes to encoded. */
        idx += (word32)encLen;

        /* Write out characters but not NUL char. */
        if (wolfSSL_BIO_write(bp, buf, (int)bufLen - 1) != (int)(bufLen - 1)) {
            err = 1;
        }
    }

    if (err) {
        /* Return 0 on error. */
        len = 0;
    }
    /* Return total number of characters written. */
    return len * 2;
}
#endif /* !NO_BIO */

#ifndef NO_ASN
/* Determine if a pad byte is required and its value for a number.
 *
 * Assumes values pointed to by pad and padVal are both 0.
 *
 * @param [in]       data    Number encoded as big-endian bytes.
 * @param [in]       len     Length of number in bytes.
 * @param [in, out]  neg     Indicates number is negative.
 * @param [out]      pad     Number of padding bytes required.
 * @param [out]      padVal  Padding byte to prepend.
 */
static void wolfssl_asn1_integer_pad(unsigned char* data, int len,
    unsigned char* neg, char* pad, unsigned char* padVal)
{
    /* Check for empty data. */
    if (len == 0) {
        *pad = 1;
        *padVal = 0x00;
        *neg = 0;
    }
    else {
        /* Get first, most significant, byte of encoded number. */
        unsigned char firstByte = data[0];

        /* 0 can't be negative. */
        if ((len == 1) && (firstByte == 0x00)) {
            *neg = 0;
        }
        /* Positive value must not have top bit of first byte set. */
        if ((!*neg) && (firstByte >= 0x80)) {
            *pad = 1;
            *padVal = 0x00;
        }
        /* Negative numbers are two's complemented.
         * Two's complement value must have top bit set.
         */
        else if (*neg && (firstByte > 0x80)) {
            *pad = 1;
            *padVal = 0xff;
        }
        /* Checking for: 0x80[00]*
         * when negative that when two's complemented will be: 0x80[00]*
         * and therefore doesn't require pad byte.
         */
        else if (*neg && (firstByte == 0x80)) {
            int i;
            /* Check rest of bytes. */
            for (i = 1; i < len; i++) {
                if (data[i] != 0x00) {
                    /* Not 0x80[00]* */
                    *pad = 1;
                    *padVal = 0xff;
                    break;
                }
            }
        }
    }
}

/* Convert ASN.1 INTEGER object into content octets.
 *
 * TODO: compatibility with OpenSSL? OpenSSL assumes data not DER encoded.
 *
 * When pp points to a buffer, on success pp will point to after the encoded
 * data.
 *
 * @param [in]      a   ASN.1 INTEGER object.
 * @param [in, out] pp  Pointer to buffer. May be NULL. Cannot point to NULL.
 * @return  Length of encoding on success.
 * @return  0 when a is NULL, pp points to NULL or DER length encoding invalid.
 */
int wolfSSL_i2c_ASN1_INTEGER(WOLFSSL_ASN1_INTEGER *a, unsigned char **pp)
{
    int err = 0;
    int len = 0;
    char pad = 0;
    unsigned char padVal = 0;
    word32 idx = 1;

    WOLFSSL_ENTER("wolfSSL_i2c_ASN1_INTEGER");

    /* Validate parameters. */
    if ((a == NULL) || ((pp != NULL) && (*pp == NULL))) {
        err = 1;
    }

    /* Get length from DER encoding. */
    if ((!err) && (GetLength_ex(a->data, &idx, &len, a->dataMax, 1) < 0)) {
        err = 1;
    }

    if (!err) {
        /* Determine pad length and value. */
        wolfssl_asn1_integer_pad(a->data + idx, len, &a->negative, &pad,
            &padVal);
        /* Total encoded length is number length plus one when padding. */
        len += (int)pad;
    }

    /* Check buffer supplied to write into. */
    if ((!err) && (pp != NULL)) {
        /* Put in any pad byte. */
        if (pad) {
            (*pp)[0] = padVal;
        }
        /* Copy remaining bytes into output buffer. */
        XMEMCPY(*pp + pad, a->data + idx, (size_t)(len - pad));
        /* Two's complement copied bytes when negative. */
        if (a->negative) {
            wolfssl_twos_compl(*pp + pad, len - pad);
        }
        /* Move pointer past encoded data. */
        *pp += len;
    }

    return len;
}

/* Make a big number with the value in the ASN.1 INTEGER object.
 *
 * A new big number object is allocated when bn is NULL.
 *
 * @param [in] ai  ASN.1 INTEGER object.
 * @param [in] bn  Big number object. May be NULL.
 * @return  Big number object on success.
 * @return  NULL when ai is NULL or converting from binary fails.
 */
WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
    WOLFSSL_BIGNUM *bn)
{
    int err = 0;
    word32 idx = 1;
    int len = 0;
    WOLFSSL_BIGNUM* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_INTEGER_to_BN");

    /* Validate parameters. */
    if (ai == NULL) {
        err = 1;
    }

    if (!err) {
        /* Get the length of ASN.1 INTEGER number. */
        if ((ai->data[0] != ASN_INTEGER) || (GetLength(ai->data, &idx, &len,
                (word32)ai->length) <= 0)) {
        #if defined(WOLFSSL_QT) || defined(WOLFSSL_HAPROXY)
            idx = 0;
            len = ai->length;
        #else
            WOLFSSL_MSG("Data in WOLFSSL_ASN1_INTEGER not DER encoded");
            err = 1;
        #endif
        }
    }
    if (!err) {
        /* Convert binary to big number. */
        ret = wolfSSL_BN_bin2bn(ai->data + idx, len, bn);
        if (ret != NULL) {
            /* Handle negative. */
            (void)wolfssl_bn_set_neg(ret, ai->negative);
        }
    }

    return ret;
}
#endif /* !NO_ASN */

/* Create an ASN.1 INTEGER object from big number.
 *
 * Allocates a new ASN.1 INTEGER object when ai is NULL.
 *
 * @param [in] bn  Big number to encode.
 * @param [in] ai  ASN.1 INTEGER object. May be NULL.
 * @return  ASN.1 INTEGER object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_INTEGER* wolfSSL_BN_to_ASN1_INTEGER(const WOLFSSL_BIGNUM *bn,
    WOLFSSL_ASN1_INTEGER *ai)
{
    int err = 0;
    WOLFSSL_ASN1_INTEGER* a = NULL;
    int len = 0;
    int numBits = 0;
    byte firstByte = 0;

    WOLFSSL_ENTER("wolfSSL_BN_to_ASN1_INTEGER");

    /* Validate parameters. */
    if (bn == NULL) {
        err = 1;
    }
    /* Use ASN.1 INTEGER object if provided. */
    else if (ai != NULL) {
        a = ai;
    }
    /* Create an ASN.1 INTEGER object to return. */
    else {
        a = wolfSSL_ASN1_INTEGER_new();
        if (a == NULL) {
            err = 1;
        }
    }

    /* Check we have an ASN.1 INTEGER object to set. */
    if (!err) {
        int length;

        /* Set type and negative. */
        a->type = WOLFSSL_V_ASN1_INTEGER;
        if (wolfSSL_BN_is_negative(bn) && !wolfSSL_BN_is_zero(bn)) {
            a->negative = 1;
            a->type |= WOLFSSL_V_ASN1_NEG_INTEGER;
        }

        /* Get length in bytes of encoded number. */
        len = wolfSSL_BN_num_bytes(bn);
        if (len == 0) {
            len = 1;
        }
        /* Get length in bits of encoded number. */
        numBits = wolfSSL_BN_num_bits(bn);
        /* Leading zero required if most-significant byte has top bit set. */
        if ((numBits > 0) && (numBits % 8) == 0) {
            firstByte = 0x80;
        }
        /* Get length of header based on length of number. */
        length = SetASNInt(len, firstByte, NULL);
        /* Add number of bytes to encode number. */
        length += len;

        /* Update data field to handle length. */
        if (wolfssl_asn1_integer_require_len(a, length, 0) != 1) {
            err = 1;
        }
    }
    if (!err) {
        /* Write ASN.1 header. */
        int idx = SetASNInt(len, firstByte, a->data);

        /* Populate data. */
        if (numBits == 0) {
            a->data[idx] = 0;
        }
        else {
            /* Add encoded number. */
            len = wolfSSL_BN_bn2bin(bn, a->data + idx);
            if (len < 0) {
                err = 1;
            }
        }

        /* Set length to encoded length. */
        a->length = idx + len;
    }

    if (err) {
        /* Can't use ASN.1 INTEGER object. */
        if (a != ai) {
            wolfSSL_ASN1_INTEGER_free(a);
        }
        a = NULL;
    }
    return a;
}

/* Get the value of the ASN.1 INTEGER as a long.
 *
 * Returning 0 on NULL and -1 on error is consistent with OpenSSL.
 *
 * @param [in] a  ASN.1 INTEGER object.
 * @return  Value as a long.
 * @return  0 when a is NULL.
 * @return  -1 when a big number operation fails.
 */
long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER* a)
{
    long ret = 1;
    WOLFSSL_BIGNUM* bn = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_INTEGER_get");

    /* Validate parameter. */
    if (a == NULL) {
        ret = 0;
    }

    if (ret > 0) {
        /* Create a big number from the DER encoding. */
        bn = wolfSSL_ASN1_INTEGER_to_BN(a, NULL);
        if (bn == NULL) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret > 0) {
        /* Get the big number as a word. */
        ret = (long)wolfSSL_BN_get_word(bn);
        /* Negate number of ASN.1 INTEGER was negative. */
        if (a->negative == 1) {
            ret = -ret;
        }
    }

    /* Dispose of big number as no longer needed. */
    if (bn != NULL) {
        wolfSSL_BN_free(bn);
    }

    WOLFSSL_LEAVE("wolfSSL_ASN1_INTEGER_get", (int)ret);

    return ret;
}

/* Sets the value of the ASN.1 INTEGER object to the long value.
 *
 * @param [in, out] a  ASN.1 INTEGER object.
 * @param [in]      v  Value to set.
 * @return  1 on success.
 * @return  0 when a is NULL.
 */
int wolfSSL_ASN1_INTEGER_set(WOLFSSL_ASN1_INTEGER *a, long v)
{
    int ret = 1;

    /* Validate parameters. */
    if (a == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        byte j;
        unsigned int i = 0;
        byte tmp[sizeof(long)];
        byte pad = 0;

        wolfssl_asn1_integer_reset_data(a);

        /* Check for negative. */
        if (v < 0) {
            /* Set negative and 2's complement the value. */
            a->negative = 1;
            a->type |= WOLFSSL_V_ASN1_NEG;
            v = -v;
        }

        /* Put value into temporary buffer - at least one byte encoded. */
        tmp[0] = (byte)(v & 0xff);
        v >>= 8;
        for (j = 1; j < (byte)sizeof(long); j++) {
            if (v == 0) {
                break;
            }
            tmp[j] = (byte)(v & 0xff);
            v >>= 8;
        }
        /* Pad with 0x00 to indicate positive number when top bit set. */
        if ((!a->negative) && (tmp[j-1] & 0x80)) {
            pad = 1;
        }

        /* Set tag. */
        a->data[i++] = ASN_INTEGER;
        /* Set length of encoded value. */
        a->data[i++] = pad + j;
        /* Set length of DER encoding. +2 for tag and length */
        a->length = 2 + pad + j;

        /* Add pad byte if required. */
        if (pad == 1) {
            a->data[i++] = 0;
        }
        /* Copy in data. */
        for (; j > 0; j--) {
            a->data[i++] = tmp[j-1];
        }
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * ASN1_OBJECT APIs
 ******************************************************************************/

#if !defined(NO_ASN)
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Create a new ASN.1 OBJECT_ID object.
 *
 * @return  ASN.1 OBJECT_ID object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_new(void)
{
    WOLFSSL_ASN1_OBJECT* obj;

    /* Allocate memory for new ASN.1 OBJECT. */
    obj = (WOLFSSL_ASN1_OBJECT*)XMALLOC(sizeof(WOLFSSL_ASN1_OBJECT), NULL,
        DYNAMIC_TYPE_ASN1);
    if (obj != NULL) {
        XMEMSET(obj, 0, sizeof(WOLFSSL_ASN1_OBJECT));
        /* Setup pointers. */
        obj->d.ia5 = &(obj->d.ia5_internal);
    #if defined(OPENSSL_ALL)
        obj->d.iPAddress = &(obj->d.iPAddress_internal);
    #endif
        /* Object was allocated. */
        obj->dynamic |= WOLFSSL_ASN1_DYNAMIC;
    }

    return obj;
}

/* Dispose of any ASN.1 OBJECT_ID dynamically allocated data.
 *
 * Do not use obj after calling this function.
 *
 * @param [in, out] obj  ASN.1 OBJECT_ID object.
 */
void wolfSSL_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT* obj)
{
    if (obj != NULL) {
        /* Check for dynamically allocated copy of encoded data. */
        if ((obj->dynamic & WOLFSSL_ASN1_DYNAMIC_DATA) != 0) {
        #ifdef WOLFSSL_DEBUG_OPENSSL
            WOLFSSL_MSG("Freeing ASN1 data");
        #endif
            XFREE((void*)obj->obj, obj->heap, DYNAMIC_TYPE_ASN1);
            obj->obj = NULL;
        }
    #if defined(OPENSSL_EXTRA)
        /* Check for path length ASN.1 INTEGER - X.509 extension. */
        if (obj->pathlen != NULL) {
            wolfSSL_ASN1_INTEGER_free(obj->pathlen);
            obj->pathlen = NULL;
        }
    #endif
        /* Check whether object was dynamically allocated. */
        if ((obj->dynamic & WOLFSSL_ASN1_DYNAMIC) != 0) {
    #ifdef WOLFSSL_DEBUG_OPENSSL
            WOLFSSL_MSG("Freeing ASN1 OBJECT");
    #endif
            XFREE(obj, NULL, DYNAMIC_TYPE_ASN1);
        }
    }
}

/* Duplicate the ASN.1 OBJECT_ID object.
 *
 * @param [in] obj  ASN.1 OBJECT_ID object to copy.
 * @return  New ASN.1 OBJECT_ID object on success.
 * @return  NULL when obj is NULL or dynamic memory allocation fails.
 */
WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_dup(WOLFSSL_ASN1_OBJECT* obj)
{
    WOLFSSL_ASN1_OBJECT* dupl = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_OBJECT_dup");

    /* Validate parameter. */
    if (obj == NULL) {
        WOLFSSL_MSG("Bad parameter");
    }
    /* Create a new ASN.1 OBJECT_ID object to return. */
    else if ((dupl = wolfSSL_ASN1_OBJECT_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_ASN1_OBJECT_new error");
    }
    if (dupl != NULL) {
        /* Copy short name. */
        XMEMCPY(dupl->sName, obj->sName, WOLFSSL_MAX_SNAME);
        /* Copy simple fields. */
        dupl->type  = obj->type;
        dupl->grp   = obj->grp;
        dupl->nid   = obj->nid;
        dupl->objSz = obj->objSz;
    #ifdef OPENSSL_EXTRA
        dupl->ca    = obj->ca;
        if (obj->pathlen != NULL) {
            dupl->pathlen = wolfSSL_ASN1_INTEGER_dup(obj->pathlen);
            if (dupl->pathlen == NULL) {
                WOLFSSL_MSG("ASN1 pathlen alloc error");
                wolfSSL_ASN1_OBJECT_free(dupl);
                dupl = NULL;
            }
        }
    #endif
        /* Check for encoding. */
        if (dupl != NULL && obj->obj) {
            /* Allocate memory for ASN.1 OBJECT_ID DER encoding. */
            dupl->obj = (const unsigned char*)XMALLOC(obj->objSz, NULL,
                DYNAMIC_TYPE_ASN1);
            if (dupl->obj == NULL) {
                WOLFSSL_MSG("ASN1 obj malloc error");
                wolfSSL_ASN1_OBJECT_free(dupl);
                dupl = NULL;
            }
            else {
                /* Encoding buffer was dynamically allocated. */
                dupl->dynamic |= WOLFSSL_ASN1_DYNAMIC_DATA;
                /* Copy DER encoding. */
                XMEMCPY((byte*)dupl->obj, obj->obj, obj->objSz);
            }
        }
    }

    return dupl;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
#endif /* !NO_ASN */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

/**
 * Parse DER encoding and return header information.
 *
 * *in is moved to the value of the ASN1 object
 *
 * @param [in, out] in     Pointer to BER encoded data.
 * @param [out]     len    Length of parsed ASN1 object
 * @param [out]     tag    Tag value of parsed ASN1 object
 * @param [out]     cls    Class of parsed ASN1 object
 * @param [in]      inLen  Length of *in buffer
 * @return int  Depends on which bits are set in the returned int:
 *              0x80 an error occurred during parsing.
 *              0x20 parsed object is constructed.
 *              0x01 the parsed object length is indefinite.
 */
int wolfSSL_ASN1_get_object(const unsigned char **in, long *len, int *tag,
    int *cls, long inLen)
{
    int err = 0;
    word32 inOutIdx = 0;
    int l = 0;
    byte t = 0;
    int ret = 0x80;

    WOLFSSL_ENTER("wolfSSL_ASN1_get_object");

    if ((in == NULL) || (*in == NULL) || (len == NULL) || (tag == NULL) ||
            (cls == NULL) || (inLen <= 0)) {
        WOLFSSL_MSG("Bad parameter");
        err = 1;
    }
    if (!err) {
        /* Length at least 1, parameters valid - cannot fail to get tag. */
        err = GetASNTag(*in, &inOutIdx, &t, (word32)inLen);
        if (!err){
            /* Get length in DER encoding. */
            if (GetLength_ex(*in, &inOutIdx, &l, (word32)inLen, 0) < 0) {
                WOLFSSL_MSG("GetLength error");
                err = 1;
            }
        }
    }
    if (!err) {
        /* Return header information. */
        *tag = t & ASN_TYPE_MASK;  /* Tag number is 5 lsb */
        *cls = t & ASN_CLASS_MASK; /* Class is 2 msb */
        *len = l;
        ret = t & ASN_CONSTRUCTED;

        if (l > (int)(inLen - inOutIdx)) {
            /* Still return other values but indicate error in msb */
            ret |= 0x80;
        }

        /* Move pointer to after DER header. */
        *in += inOutIdx;
    }

    return ret;
}

int wolfssl_asn1_obj_set(WOLFSSL_ASN1_OBJECT* obj, const byte* der, word32 len,
        int addHdr)
{
    word32 idx = 0;

    if (obj == NULL || der == NULL || len == 0)
        return WOLFSSL_FAILURE;

    if (addHdr)
        idx = SetHeader(ASN_OBJECT_ID, (word32)len, NULL, 0);

    if (obj->obj != NULL) {
        XFREE((void*)obj->obj, obj->heap, DYNAMIC_TYPE_ASN1);
        obj->obj = NULL;
        obj->dynamic &= ~WOLFSSL_ASN1_DYNAMIC_DATA;
    }

    obj->obj =(unsigned char*)XMALLOC(idx + len, obj->heap, DYNAMIC_TYPE_ASN1);
    if (obj->obj == NULL)
        return WOLFSSL_FAILURE;

    if (addHdr)
        SetHeader(ASN_OBJECT_ID, (word32)len, (byte*)obj->obj, 0);

    XMEMCPY((byte*)obj->obj + idx, der, len);
    obj->objSz = (unsigned int)(idx + len);
    obj->dynamic |= WOLFSSL_ASN1_DYNAMIC_DATA;
    return WOLFSSL_SUCCESS;
}

/* Creates and ASN.1 OBJECT_ID object from DER encoding.
 *
 * @param [out]     a       Pointer to return new ASN.1 OBJECT_ID through.
 * @param [in, out] der     Pointer to buffer holding DER encoding.
 * @param [in]      length  Length of DER encoding in bytes.
 * @return  New ASN.1 OBJECT_ID object on success.
 * @return  NULL when der or *der is NULL or length is less than or equal zero.
 * @return  NULL when not an OBJECT_ID or decoding fails.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_OBJECT *wolfSSL_d2i_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT **a,
    const unsigned char **der, long length)
{
    WOLFSSL_ASN1_OBJECT* ret = NULL;
    int len = 0;
    word32 idx = 0;
    word32 maxIdx;

    WOLFSSL_ENTER("wolfSSL_d2i_ASN1_OBJECT");

    /* Validate parameters. */
    if ((der == NULL) || (*der == NULL) || (length <= 0)) {
        WOLFSSL_MSG("Bad parameter");
        return NULL;
    }

    /* An ASN.1 OBJECT is an OID, whose DER encoding cannot exceed the OID
     * ceiling: a tag byte, a single short-form length byte (content is at
     * most MAX_OID_SZ, which is below the long-form threshold) and the OID
     * content. Cap the parse window so an oversized length argument cannot
     * drive the header decode to read past the end of the actual buffer. */
    maxIdx = (word32)length;
    if (maxIdx > (word32)(MAX_OID_SZ + 2)) {
        maxIdx = (word32)(MAX_OID_SZ + 2);
    }

    if (GetASNHeader(*der, ASN_OBJECT_ID, &idx, &len, maxIdx) < 0) {
        WOLFSSL_MSG("error getting tag");
        return NULL;
    }

    if (len <= 0) {
        WOLFSSL_MSG("zero length");
        return NULL;
    }

    ret = wolfSSL_ASN1_OBJECT_new();
    if (ret == NULL) {
        WOLFSSL_MSG("wolfSSL_ASN1_OBJECT_new error");
        return NULL;
    }

    if (wolfssl_asn1_obj_set(ret, *der, idx + len, 0) != WOLFSSL_SUCCESS) {
        wolfSSL_ASN1_OBJECT_free(ret);
        return NULL;
    }

    *der += idx + len;
    if (a != NULL) {
        if (*a != NULL)
            wolfSSL_ASN1_OBJECT_free(*a);
        *a = ret;
    }

    return ret;
}

/* Write out DER encoding of ASN.1 OBJECT_ID.
 *
 * When pp is NULL, length is returned.
 * When pp points to NULL, a new buffer is allocated and returned through pp.
 * When pp points to a buffer, it is moved on past encoded data on success.
 *
 * @param [in]      a   ASN.1 OBJECT_ID object.
 * @param [in, out] pp  Pointer to buffer to write to. May be NULL.
 * @return  Length of encoding on success.
 * @return  0 when a or encoding buffer is NULL.
 * @return  0 when dynamic memory allocation fails.
 */
int wolfSSL_i2d_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT *a, unsigned char **pp)
{
    int len = 0;

    WOLFSSL_ENTER("wolfSSL_i2d_ASN1_OBJECT");

    /* Validate parameters */
    if ((a == NULL) || (a->obj == NULL)) {
        WOLFSSL_MSG("Bad parameters");
    }
    /* Only return length when no pointer supplied. */
    else if (pp == NULL) {
        len = (int)a->objSz;
    }
    else {
        byte *p = NULL;

        /* Check if we have a buffer to encode into. */
        if (*pp == NULL) {
            /* Allocate a new buffer to return. */
            p = (byte*)XMALLOC(a->objSz, NULL, DYNAMIC_TYPE_OPENSSL);
            if (p == NULL) {
                WOLFSSL_MSG("Bad malloc");
            }
            else {
                /* Return allocated buffer. */
                *pp = p;
            }
        }

        /* Check we have a buffer to encode into. */
        if (*pp != NULL) {
            /* Copy in DER encoding. */
            XMEMCPY(*pp, a->obj, a->objSz);
            /* Move on pointer if user supplied. */
            if (p == NULL) {
                *pp += a->objSz;
            }
            /* Return length of DER encoding. */
            len = (int)a->objSz;
        }
    }

    return len;
}

/* Create an ASN.1 OBJECT_ID object from the content octets.
 *
 * @param [out]     a    Pointer to return ASN.1 OBJECT_ID object.
 * @param [in, out] pp   Pointer to buffer holding content octets.
 * @param [in]      len  Length of content octets in bytes.
 * @return  New ASN.1 OBJECT_ID object on success.
 * @return  NULL when pp or *pp is NULL or length is less than or equal zero.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_OBJECT *wolfSSL_c2i_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT **a,
        const unsigned char **pp, long len)
{
    WOLFSSL_ASN1_OBJECT* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_c2i_ASN1_OBJECT");

    /* Validate parameters. */
    if ((pp == NULL) || (*pp == NULL) || (len <= 0)) {
        WOLFSSL_MSG("Bad parameter");
        return NULL;
    }

    /* Create a new ASN.1 OBJECT_ID object. */
    ret = wolfSSL_ASN1_OBJECT_new();
    if (ret == NULL) {
        WOLFSSL_MSG("wolfSSL_ASN1_OBJECT_new error");
        return NULL;
    }

    if (wolfssl_asn1_obj_set(ret, *pp, (word32)len, 1) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfssl_asn1_obj_set error");
        wolfSSL_ASN1_OBJECT_free(ret);
        return NULL;
    }

    /* Move pointer to after data copied out. */
    *pp += len;
    /* Return ASN.1 OBJECT_ID object through a if required. */
    if (a != NULL) {
        if (*a != NULL)
            wolfSSL_ASN1_OBJECT_free(*a);
        *a = ret;
    }

    return ret;
}

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA

/* Write at most buf_len bytes of textual representation of ASN.1 OBJECT_ID.
 *
 * @param [in, out] buf      Buffer to write to.
 * @param [in]      buf_len  Length of buffer in bytes.
 * @param [in]      a        ASN.1 OBJECT_ID object.
 * @return  Number of bytes written on success.
 * @return  0 on failure.
 */
int wolfSSL_i2t_ASN1_OBJECT(char *buf, int buf_len, WOLFSSL_ASN1_OBJECT *a)
{
    WOLFSSL_ENTER("wolfSSL_i2t_ASN1_OBJECT");

    return wolfSSL_OBJ_obj2txt(buf, buf_len, a, 0);
}

#ifndef NO_BIO
/* Write out the text encoding of the ASN.1 OBJECT_ID.
 *
 * @param [in] bp  BIO to write to.
 * @param [in] a   ASN.1 OBJECT_ID object.
 * @return  Number of bytes written on success.
 * @return  0 on failure.
 */
int wolfSSL_i2a_ASN1_OBJECT(WOLFSSL_BIO *bp, WOLFSSL_ASN1_OBJECT *a)
{
    int length = 0;
    int cLen = 0;
    word32 idx = 0;
    const char null_str[] = "NULL";
    const char invalid_str[] = "<INVALID>";
    char buf[80];

    WOLFSSL_ENTER("wolfSSL_i2a_ASN1_OBJECT");

    /* Validate parameters. */
    if (bp == NULL) {
        /* Do nothing. */
    }
    /* NULL object is written as "NULL". */
    else if (a == NULL) {
        /* Write "NULL" - as done in OpenSSL. */
        length = wolfSSL_BIO_write(bp, null_str, (int)XSTRLEN(null_str));
    }
    /* Try getting text version and write it out. */
    else if ((length = wolfSSL_i2t_ASN1_OBJECT(buf, sizeof(buf), a)) > 0) {
        length = wolfSSL_BIO_write(bp, buf, length);
    }
    /* Look for DER header. */
    else if ((a->obj == NULL) || (a->obj[idx++] != ASN_OBJECT_ID)) {
        WOLFSSL_MSG("Bad ASN1 Object");
    }
    /* Get length from DER header. */
    else if (GetLength((const byte*)a->obj, &idx, &cLen, a->objSz) < 0) {
        length = 0;
    }
    else {
        /* Write out "<INVALID>" and dump content. */
        length = wolfSSL_BIO_write(bp, invalid_str, (int)XSTRLEN(invalid_str));
        length += wolfSSL_BIO_dump(bp, (const char*)(a->obj + idx), cLen);
    }

    return length;
}
#endif /* !NO_BIO */

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * ASN1_SK_OBJECT APIs
 ******************************************************************************/

#if (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && !defined(NO_ASN)
/* Create a new WOLFSSL_ASN1_OBJECT stack.
 *
 * @return  New WOLFSSL_ASN1_OBJECT stack on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_STACK* wolfSSL_sk_new_asn1_obj(void)
{
    WOLFSSL_ENTER("wolfSSL_sk_new_asn1_obj");

    return wolfssl_sk_new_type(STACK_TYPE_OBJ);
}

/* Dispose of WOLFSL_ASN1_OBJECT stack.
 *
 * @param [in, out] sk  Stack to free nodes in.
 */
void wolfSSL_sk_ASN1_OBJECT_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk)
{
    /* Dispose of stack. */
    wolfSSL_sk_free(sk);
}

/* Dispose of all ASN.1 OBJECT_ID objects in ASN1_OBJECT stack.
 *
 * This is different then wolfSSL_ASN1_OBJECT_free in that it allows for
 * choosing the function to use when freeing an ASN1_OBJECT stack.
 *
 * @param [in, out] sk  ASN.1 OBJECT_ID stack to free.
 * @param [in]      f   Free function to apply to each ASN.1 OBJECT_ID object.
 */
void wolfSSL_sk_ASN1_OBJECT_pop_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk,
    void (*f) (WOLFSSL_ASN1_OBJECT*))
{
    WOLFSSL_ENTER("wolfSSL_sk_ASN1_OBJECT_pop_free");
    wolfSSL_sk_pop_free(sk, (wolfSSL_sk_freefunc)f);
}

/* Push a WOLFSSL_ASN1_OBJECT onto stack.
 *
 * @param [in, out] sk   ASN.1 OBJECT_ID stack.
 * @param [in]      obj  ASN.1 OBJECT_ID object to push on. Cannot be NULL.
 * @return  1 on success.
 * @return  0 when sk or obj is NULL.
 * @return  0 when dynamic memory allocation fails.
 */
int wolfSSL_sk_ASN1_OBJECT_push(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk,
    WOLFSSL_ASN1_OBJECT* obj)
{
    WOLFSSL_ENTER("wolfSSL_sk_ASN1_OBJECT_push");

    return wolfSSL_sk_push(sk, obj);
}

/* Pop off a WOLFSSL_ASN1_OBJECT from the stack.
 *
 * @param [in, out] sk  ASN.1 OBJECT_ID stack.
 * @return  ASN.1 OBJECT_ID object on success.
 * @return  NULL when stack is NULL or no nodes left in stack.
 */
WOLFSSL_ASN1_OBJECT* wolfSSL_sk_ASN1_OBJECT_pop(
    WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk)
{
    return (WOLFSSL_ASN1_OBJECT*)wolfssl_sk_pop_type(sk, STACK_TYPE_OBJ);
}

#endif /* (OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL) && !NO_ASN */

/*******************************************************************************
 * ASN1_STRING APIs
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)

/* Create a new ASN.1 STRING object.
 *
 * @return  New ASN.1 STRING object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_new(void)
{
    WOLFSSL_ASN1_STRING* asn1;

#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_new");
#endif

    asn1 = (WOLFSSL_ASN1_STRING*)XMALLOC(sizeof(WOLFSSL_ASN1_STRING), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (asn1 != NULL) {
        XMEMSET(asn1, 0, sizeof(WOLFSSL_ASN1_STRING));
    }

    return asn1;
}

/* Create a new ASN.1 STRING object.
 *
 * @param [in] type  Encoding type.
 * @return  New ASN.1 STRING object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_type_new(int type)
{
    WOLFSSL_ASN1_STRING* asn1;

#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_type_new");
#endif

    asn1 = wolfSSL_ASN1_STRING_new();
    if (asn1 != NULL) {
        asn1->type = type;
    }

    return asn1;
}

/* Dispose of ASN.1 STRING object.
 *
 * @param [in, out] asn1  ASN.1 STRING object.
 */
void wolfSSL_ASN1_STRING_free(WOLFSSL_ASN1_STRING* asn1)
{
#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_free");
#endif

    /* Check we have an object to free. */
    if (asn1 != NULL) {
        /* Dispose of dynamic data. */
        if ((asn1->length > 0) && asn1->isDynamic) {
            XFREE(asn1->data, NULL, DYNAMIC_TYPE_OPENSSL);
        }
    }
    /* Dispose of ASN.1 STRING object. */
    XFREE(asn1, NULL, DYNAMIC_TYPE_OPENSSL);
}

/* Copy an ASN.1 STRING object from src into dest.
 *
 * @param [in, out] dest  ASN.1 STRING object to copy into.
 * @param [in]      src   ASN.1 STRING object to copy from.
 */
int wolfSSL_ASN1_STRING_copy(WOLFSSL_ASN1_STRING* dest,
    const WOLFSSL_ASN1_STRING* src)
{
    int ret = 1;

    /* Validate parameters. */
    if ((src == NULL) || (dest == NULL)) {
        ret = 0;
    }
    /* Set the DER encoding. */
    if ((ret == 1) && (wolfSSL_ASN1_STRING_set(dest, src->data, src->length) !=
            1)) {
        ret = 0;
    }
    if (ret == 1) {
        /* Copy simple fields. */
        dest->type  = src->type;
        dest->flags = src->flags;
    }

    return ret;
}

/* Duplicate an ASN.1 STRING object.
 *
 * @param [in] asn1  ASN.1 STRING object to duplicate.
 * @return  New ASN.1 STRING object on success.
 * @return  NULL when asn1 is NULL or dynamic memory allocation fails.
 */
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_dup(WOLFSSL_ASN1_STRING* asn1)
{
    WOLFSSL_ASN1_STRING* dupl = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_dup");

    /* Check we have an object to duplicate. */
    if (asn1 == NULL) {
        WOLFSSL_MSG("Bad parameter");
    }
    else {
        /* Create a new ASN.1 STRING object. */
        dupl = wolfSSL_ASN1_STRING_new();
        if (dupl == NULL) {
            WOLFSSL_MSG("wolfSSL_ASN1_STRING_new error");
        }
    }

    if (dupl != NULL) {
        /* Copy the contents. */
        if (wolfSSL_ASN1_STRING_copy(dupl, asn1) != 1) {
            WOLFSSL_MSG("wolfSSL_ASN1_STRING_copy error");
            /* Dispose of duplicate and return NULL. */
            wolfSSL_ASN1_STRING_free(dupl);
            dupl = NULL;
        }
    }

    return dupl;
}

/* Compare two ASN.1 STRING objects.
 *
 * Compares type when data the same.
 *
 * @param [in] a  First ASN.1 STRING object.
 * @param [in] b  Second ASN.1 STRING object.
 * @return Negative value when a is less than b.
 * @return 0 when a equals b.
 * @return Positive value when a is greater than b.
 * @return WOLFSSL_FATAL_ERROR when a or b is NULL.
 */
int wolfSSL_ASN1_STRING_cmp(const WOLFSSL_ASN1_STRING *a,
    const WOLFSSL_ASN1_STRING *b)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_cmp");

    /* Validate parameters. */
    if ((a == NULL) || (b == NULL)) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    /* Compare length of data. */
    else if (a->length != b->length) {
        ret = a->length - b->length;
    }
    /* Compare data. */
    else if ((ret = XMEMCMP(a->data, b->data, (size_t)a->length)) == 0) {
        /* Compare ASN.1 types - wolfSSL_ASN1_STRING_type_new(). */
        ret = a->type - b->type;
    }

    return ret;
}

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA)
#if !defined(NO_CERTS)
#ifndef NO_WOLFSSL_STUB
WOLFSSL_ASN1_STRING* wolfSSL_d2i_DISPLAYTEXT(WOLFSSL_ASN1_STRING **asn,
    const unsigned char **in, long len)
{
    WOLFSSL_STUB("d2i_DISPLAYTEXT");
    (void)asn;
    (void)in;
    (void)len;
    return NULL;
}
#endif
#endif /* !NO_CERTS */
#endif /* OPENSSL_EXTRA */

#ifndef NO_ASN
#if defined(OPENSSL_EXTRA)
/* Convert ASN.1 STRING that is UniversalString type to PrintableString type.
 *
 * @param [in, out] s  ASN.1 STRING object to convert.
 * @return  1 on success.
 * @return  0 when s is NULL.
 * @return  0 when type is not UniversalString or string is not of that format.
 */
int wolfSSL_ASN1_UNIVERSALSTRING_to_string(WOLFSSL_ASN1_STRING *s)
{
    int ret = 1;
    char* p;

    WOLFSSL_ENTER("wolfSSL_ASN1_UNIVERSALSTRING_to_string");

    /* Validate parameter. */
    if (s == NULL) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }

    /* Check type of ASN.1 STRING. */
    if ((ret == 1) && (s->type != WOLFSSL_V_ASN1_UNIVERSALSTRING)) {
        WOLFSSL_MSG("Input is not a universal string");
        ret = 0;
    }

    /* Check length is indicative of UNIVERSAL_STRING. */
    if ((ret == 1) && ((s->length % 4) != 0)) {
        WOLFSSL_MSG("Input string must be divisible by 4");
        ret = 0;
    }

    if (ret == 1) {
        /* Ensure each UniversalString character looks right. */
        for (p = s->data; p < s->data + s->length; p += 4)
            if ((p[0] != '\0') || (p[1] != '\0') || (p[2] != '\0'))
                break;
        /* Check whether we failed loop early. */
        if (p != s->data + s->length) {
            WOLFSSL_MSG("Wrong string format");
            ret = 0;
        }
    }

    if (ret == 1) {
        char* copy;

        /* Strip first three bytes of each four byte character. */
        for (copy = p = s->data; p < s->data + s->length; p += 4) {
            *copy++ = p[3];
        }
        /* Place NUL on end. */
        *copy = '\0';
        /* Update length and type. */
        s->length /= 4;
        s->type = WOLFSSL_V_ASN1_PRINTABLESTRING;
    }

    return ret;
}
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Convert ASN.1 STRING to UTF8 encoding.
 *
 * Assumes stored encoding is UTF8.
 * Returned buffer should be freed using OPENSSL_free().
 *
 * @param [out] out   Pointer to return allocated string.
 * @param [in]  asn1  ASN.1 STRING object.
 * @return  Length of string, excluding NUL, on success.
 * @return  -1 when out or asn1 is NULL.
 * @return  -1 when no data to return.
 * @return  -1 dynamic memory allocation fails.
 */
int wolfSSL_ASN1_STRING_to_UTF8(unsigned char **out, WOLFSSL_ASN1_STRING *asn1)
{
    unsigned char* buf = NULL;
    unsigned char* data = NULL;
    int len = -1;

    /* Validate parameters. */
    if ((out != NULL) && (asn1 != NULL)) {
        /* Get data and length. */
        data = wolfSSL_ASN1_STRING_data(asn1);
        len = wolfSSL_ASN1_STRING_length(asn1);
        /* Check data and length are usable. */
        if ((data == NULL) || (len < 0)) {
            len = WOLFSSL_FATAL_ERROR;
        }
    }
    if (len != -1) {
        /* Allocate buffer to hold string and NUL. */
        buf = (unsigned char*)XMALLOC((size_t)(len + 1), NULL,
            DYNAMIC_TYPE_OPENSSL);
        if (buf == NULL) {
            len = WOLFSSL_FATAL_ERROR;
        }
    }
    if (len != -1) {
        /* Copy in string - NUL always put on end of stored string. */
        XMEMCPY(buf, data, (size_t)(len + 1));
        /* Return buffer. */
        *out = buf;
    }

    return len;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

/* Encode ASN.1 STRING data as hex digits separated by colon.
 *
 * Assumes length is greater than 0.
 *
 * @param [in] s  ASN.1 STRING object.
 * @return  Buffer containing string representation on success.
 * @return  NULL when dynamic memory allocation fails.
 * @return  NULL when encoding a character as hex fails.
 */
static char* wolfssl_asn1_string_to_hex_chars(const WOLFSSL_ASN1_STRING *s)
{
    char* tmp;
    int tmpSz = s->length * 3;

    tmp = (char*)XMALLOC((size_t)tmpSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        WOLFSSL_MSG("Memory Error");
    }
    else {
        int i;
        unsigned char* str = (unsigned char*)s->data;

        /* Put out all but last character as a hex digit with ':'. */
        for (i = 0; i < s->length; i++) {
            /* Put in hex digit string at end of tmp. */
            ByteToHexStr(str[i], tmp + i * 3);
            /* Check not last character. */
            if (i < s->length - 1) {
                /* Put in separator: ':'. */
                tmp[i * 3 + 2] = ':';
            }
            /* Last character. */
            else {
                /* Put in NUL to terminate string. */
                tmp[i * 3 + 2] = '\0';
            }
        }
    }

    return tmp;
}

/* Create a string encoding of ASN.1 STRING object.
 *
 * @param [in] method  Method table. Unused.
 * @param [in] s       ASN.1 STRING object.
 * @return  Buffer containing string representation on success.
 * @return  NULL when s or data is NULL.
 * @return  NULL when dynamic memory allocation fails.
 * @return  NULL when encoding a character as hex fails.
 */
char* wolfSSL_i2s_ASN1_STRING(WOLFSSL_v3_ext_method *method,
    const WOLFSSL_ASN1_STRING *s)
{
    char* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_i2s_ASN1_STRING");
    (void)method;

    /* Validate parameters. */
    if ((s == NULL) || (s->data == NULL)) {
        WOLFSSL_MSG("Bad Function Argument");
    }
    /* Handle 0 length data separately. */
    else if (s->length == 0) {
        ret = (char *)XMALLOC(1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ret != NULL) {
            ret[0] = '\0';
        }
    }
    else {
        /* Convert unreadable strings to hexadecimal. */
        ret = wolfssl_asn1_string_to_hex_chars(s);
    }

    return ret;
}

static int i2d_ASN1_STRING(WOLFSSL_ASN1_STRING* s,
        unsigned char **pp, byte tag)
{
    int idx;
    int len;
    unsigned char* out;

    if (s == NULL || s->data == NULL || s->length == 0)
        return WOLFSSL_FATAL_ERROR;

    len = SetHeader(tag, s->length, NULL, 0) + s->length;

    if (pp == NULL)
        return len;

    if (*pp == NULL) {
        out = (unsigned char*)XMALLOC(len, NULL, DYNAMIC_TYPE_ASN1);
        if (out == NULL)
            return WOLFSSL_FATAL_ERROR;
    }
    else {
        out = *pp;
    }

    idx = (int)SetHeader(tag, s->length, out, 0);
    XMEMCPY(out + idx, s->data, s->length);
    if (*pp == NULL)
        *pp = out;
    else
        *pp += len;

    return len;
}

int wolfSSL_i2d_ASN1_GENERALSTRING(WOLFSSL_ASN1_STRING* s, unsigned char **pp)
{
    WOLFSSL_ENTER("wolfSSL_i2d_ASN1_GENERALSTRING");

    return i2d_ASN1_STRING(s, pp, ASN_GENERALSTRING);
}

int wolfSSL_i2d_ASN1_OCTET_STRING(WOLFSSL_ASN1_STRING* s, unsigned char **pp)
{
    WOLFSSL_ENTER("wolfSSL_i2d_ASN1_OCTET_STRING");

    return i2d_ASN1_STRING(s, pp, ASN_OCTET_STRING);
}

int wolfSSL_i2d_ASN1_UTF8STRING(WOLFSSL_ASN1_STRING* s, unsigned char **pp)
{
    WOLFSSL_ENTER("wolfSSL_i2d_ASN1_UTF8STRING");

    return i2d_ASN1_STRING(s, pp, ASN_UTF8STRING);
}

int wolfSSL_i2d_ASN1_SEQUENCE(WOLFSSL_ASN1_STRING* s,
        unsigned char **pp)
{
    unsigned char* out;

    if (s == NULL || s->data == NULL || s->length == 0)
        return WOLFSSL_FATAL_ERROR;

    if (pp == NULL)
        return s->length;

    if (*pp == NULL) {
        out = (unsigned char*)XMALLOC(s->length, NULL, DYNAMIC_TYPE_ASN1);
        if (out == NULL)
            return WOLFSSL_FATAL_ERROR;
    }
    else {
        out = *pp;
    }

    XMEMCPY(out, s->data, s->length);
    if (*pp == NULL)
        *pp = out;
    else
        *pp += s->length;

    return s->length;
}

static WOLFSSL_ASN1_STRING* d2i_ASN1_STRING(WOLFSSL_ASN1_STRING** out,
        const byte** src, long len, byte expTag)
{
    WOLFSSL_ASN1_STRING* ret = NULL;
    word32 idx = 0;
    byte tag = 0;
    int length = 0;

    WOLFSSL_ENTER("d2i_ASN1_STRING");

    if (src == NULL || *src == NULL || len <= 0)
        return NULL;

    if (GetASNTag(*src, &idx, &tag, (word32)len) < 0)
        return NULL;
    if (tag != expTag)
        return NULL;
    if (GetLength(*src, &idx, &length, (word32)len) < 0)
        return NULL;

    ret = wolfSSL_ASN1_STRING_new();
    if (ret == NULL)
        return NULL;

    if (wolfSSL_ASN1_STRING_set(ret, *src + idx, length) != 1) {
        wolfSSL_ASN1_STRING_free(ret);
        return NULL;
    }

    if (out != NULL) {
        if (*out != NULL)
            wolfSSL_ASN1_STRING_free(*out);
        *out = ret;
    }
    *src += idx + length;

    return ret;
}

WOLFSSL_ASN1_STRING* wolfSSL_d2i_ASN1_GENERALSTRING(WOLFSSL_ASN1_STRING** out,
        const byte** src, long len)
{
    WOLFSSL_ENTER("wolfSSL_d2i_ASN1_GENERALSTRING");

    return d2i_ASN1_STRING(out, src, len, ASN_GENERALSTRING);
}

WOLFSSL_ASN1_STRING* wolfSSL_d2i_ASN1_OCTET_STRING(WOLFSSL_ASN1_STRING** out,
        const byte** src, long len)
{
    WOLFSSL_ENTER("wolfSSL_d2i_ASN1_OCTET_STRING");

    return d2i_ASN1_STRING(out, src, len, ASN_OCTET_STRING);
}

WOLFSSL_ASN1_STRING* wolfSSL_d2i_ASN1_UTF8STRING(WOLFSSL_ASN1_STRING** out,
        const byte** src, long len)
{
    WOLFSSL_ENTER("wolfSSL_d2i_ASN1_UTF8STRING");

    return d2i_ASN1_STRING(out, src, len, ASN_UTF8STRING);
}

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */
#endif /* NO_ASN */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Get the type of encoding.
 *
 * @param [in] asn1  ASN.1 STRING object.
 * @return  Encoding type on success.
 * @return  0 when asn1 is NULL or no encoding set.
 */
int wolfSSL_ASN1_STRING_type(const WOLFSSL_ASN1_STRING* asn1)
{
    int type = 0;

#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_type");
#endif

    if (asn1 != NULL) {
        type = asn1->type;
    }

    return type;
}

#ifndef NO_CERTS
/* Get the pointer that is the data.
 *
 * @param [in] asn  ASN.1 STRING object.
 * @return  Buffer with string on success.
 * @return  NULL when asn is NULL or no data set.
 */
const unsigned char* wolfSSL_ASN1_STRING_get0_data(
    const WOLFSSL_ASN1_STRING* asn)
{
    char* data = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_get0_data");

    if (asn != NULL) {
        data = asn->data;
    }

    return (const unsigned char*)data;
}

/* Get the pointer that is the data.
 *
 * @param [in] asn  ASN.1 STRING object.
 * @return  Buffer with string on success.
 * @return  NULL when asn is NULL or no data set.
 */
unsigned char* wolfSSL_ASN1_STRING_data(WOLFSSL_ASN1_STRING* asn)
{
    char* data = NULL;

#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_data");
#endif

    if (asn != NULL) {
        data = asn->data;
    }

    return (unsigned char*)data;
}

/* Get the length of the data.
 *
 * @param [in] asn  ASN.1 STRING object.
 * @return  String length on success.
 * @return  0 when asn is NULL or no data set.
 */
int wolfSSL_ASN1_STRING_length(const WOLFSSL_ASN1_STRING* asn)
{
    int len = 0;

#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_length");
#endif

    if (asn) {
        len = asn->length;
    }

    return len;
}
#endif /* !NO_CERTS */

/* Set the string data.
 *
 * When sz is less than 0, the string length will be calculated using XSTRLEN.
 *
 * @param [in, out] asn1    ASN.1 STRING object.
 * @param [in]      data    String data to set.
 * @param [in]      sz      Length of data to set in bytes.
 * @return  1 on success.
 * @return  0 when asn1 is NULL or data is NULL and sz is not zero.
 * @return  0 when dynamic memory allocation fails.
 */
int wolfSSL_ASN1_STRING_set(WOLFSSL_ASN1_STRING* asn1, const void* data, int sz)
{
    int ret = 1;

#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_set");
#endif

    /* Validate parameters. */
    if ((asn1 == NULL) || ((data == NULL) && (sz != 0))) {
        ret = 0;
    }

    /* Calculate size from data if not passed in. */
    if ((ret == 1) && (sz < 0)) {
        sz = (int)XSTRLEN((const char*)data);
        if (sz < 0) {
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Cast to size_t BEFORE adding 1 to prevent signed overflow
         * when sz == INT_MAX. By this point sz >= 0 (negative sz is
         * handled above as OpenSSL -1/strlen compat). */
        size_t allocSz = (size_t)sz + 1;
        char* oldData = asn1->data;
        int oldDynamic = asn1->isDynamic;
        char* dst;

        /* Select the destination buffer WITHOUT disposing of the existing
         * data yet. Deferring the free keeps the copy below safe even when
         * the source aliases the object's own buffer (data == asn1->data),
         * avoiding a use-after-free or clear-before-copy without needing an
         * ephemeral allocation. */
        if (allocSz > CTC_NAME_SIZE) {
            /* Allocate new buffer. */
            dst = (char*)XMALLOC(allocSz, NULL, DYNAMIC_TYPE_OPENSSL);
            if (dst == NULL) {
                ret = 0;
            }
        }
        else {
            /* Use the fixed array for data. */
            dst = asn1->strData;
        }

        if (ret == 1) {
            /* Copy string and append NUL. XMEMMOVE handles the case where
             * data aliases the fixed array (source and destination overlap). */
            if (data != NULL) {
                XMEMMOVE(dst, data, (size_t)sz);
            }
            dst[sz] = '\0';

            /* Clear any remainder of the fixed array (matches prior behavior
             * of zeroing the whole array). Done after the copy so it never
             * disturbs an aliased source. */
            if (dst == asn1->strData) {
                XMEMSET(dst + sz + 1, 0, CTC_NAME_SIZE - (size_t)sz - 1);
            }

            /* Dispose of any old dynamic buffer now the copy is complete. */
            if (oldDynamic && (oldData != dst)) {
                XFREE(oldData, NULL, DYNAMIC_TYPE_OPENSSL);
            }

            /* Commit the new buffer and its properties. */
            asn1->data = dst;
            asn1->isDynamic = (allocSz > CTC_NAME_SIZE) ? 1 : 0;
            asn1->length = sz;
        }
    }

    return ret;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(WOLFCRYPT_ONLY)
#ifndef NO_CERTS

/* Make a UTF8 canonical version of ASN.1 STRING object's data.
 *
 * @param [in, out] asn  ASN.1 STRING to set.
 */
static void wolfssl_asn1_string_canonicalize(WOLFSSL_ASN1_STRING* asn)
{
    char* src = asn->data;
    char* p = asn->data + asn->length - 1;
    int len = asn->length;
    int i;

    /* Trim whitespace from the tail. */
    for (; (len > 0) && (XISSPACE((unsigned char)*p)); len--) {
        p--;
    }
    if (len > 0) {
        /* Trim whitespace from the head. */
        for (; XISSPACE((unsigned char)*src); len--) {
            src++;
        }
    }

    /* Output at the start. */
    p = asn->data;
    /* Process each character in string after trim. */
    for (i = 0; i < len; p++, i++) {
        /* Check for non-ascii character. */
        if (!XISASCII(*src)) {
            /* Keep non-ascii character as-is. */
            *p = *src++;
        }
        /* Check for whitespace. */
        else if (XISSPACE((unsigned char)*src)) {
            /* Only use space character for whitespace. */
            *p = 0x20;
            /* Skip any succeeding whitespace characters. */
            while (XISSPACE((unsigned char)*++src)) {
                i++;
            }
        }
        else {
            /* Convert to lower case. */
            *p = (char)XTOLOWER((unsigned char)*src++);
        }
    }
    /* Set actual length after canonicalization. */
    asn->length = (int)(p - asn->data);
}

/* Make a canonical version of ASN.1 STRING object in ASN.1 STRING object.
 *
 * @param [in, out] asn_out  ASN.1 STRING object to set.
 * @param [in]      asn_in   ASN.1 STRING object to get data from.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when asn_out or asn_in is NULL.
 * @return  0 when no data.
 * @return  0 when dynamic memory allocation fails.
 */
int wolfSSL_ASN1_STRING_canon(WOLFSSL_ASN1_STRING* asn_out,
    const WOLFSSL_ASN1_STRING* asn_in)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_canon");

    /* Validate parameters. */
    if ((asn_out == NULL) || (asn_in == NULL)) {
        WOLFSSL_MSG("invalid function arguments");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 1) {
        switch (asn_in->type) {
            case WOLFSSL_MBSTRING_UTF8:
            case WOLFSSL_V_ASN1_PRINTABLESTRING:
                /* Set type to UTF8. */
                asn_out->type = WOLFSSL_MBSTRING_UTF8;
                /* Dispose of any dynamic data already in asn_out. */
                if (asn_out->isDynamic) {
                    XFREE(asn_out->data, NULL, DYNAMIC_TYPE_OPENSSL);
                    asn_out->data = NULL;
                }
                /* Make ASN.1 STRING into UTF8 buffer. */
                asn_out->length = wolfSSL_ASN1_STRING_to_UTF8(
                    (unsigned char**)&asn_out->data,
                    (WOLFSSL_ASN1_STRING*)asn_in);
                /* Check for error from creating UTF8 string. */
                if (asn_out->length < 0) {
                    ret = 0;
                }
                else {
                    /* Data now dynamic after converting to UTF8. */
                    asn_out->isDynamic = 1;
                    /* Canonicalize the data. */
                    wolfssl_asn1_string_canonicalize(asn_out);
                    if (asn_out->length == 0) {
                        /* Dispose of data if canonicalization removes all
                         * characters. */
                        XFREE(asn_out->data, NULL, DYNAMIC_TYPE_OPENSSL);
                        asn_out->data = NULL;
                        asn_out->isDynamic = 0;
                    }
                }
                break;
            default:
                /* Unrecognized format - just copy. */
                WOLFSSL_MSG("just copy string");
                ret = wolfSSL_ASN1_STRING_copy(asn_out, asn_in);
        }
    }

    return ret;
}

#endif /* !NO_CERTS */
#endif /* (OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL) && !WOLFCRYPT_ONLY */

#if defined(OPENSSL_EXTRA)

#if !defined(NO_ASN)
#ifndef NO_BIO
/* Returns boolean indicating character is unprintable.
 *
 * @param [in] c  ASCII character.
 * @return  1 when character is unprintable.
 * @return  0 when character is printable.
 */
static int wolfssl_unprintable_char(char c)
{
    const unsigned char last_unprintable = 31;
    const unsigned char LF = 10;               /* Line Feed */
    const unsigned char CR = 13;               /* Carriage Return */

    return (c <= last_unprintable) && (c != LF) && (c != CR);
}

/* Print ASN.1 STRING to BIO.
 *
 * TODO: Unprintable characters conversion is destructive.
 *
 * @param [in] bio  BIO to print to.
 * @param [in] str  ASN.1 STRING to print.
 * @return  Length of string written on success.
 * @return  0 when bio or str is NULL.
 * @return  0 when writing to BIO fails.
 */
int wolfSSL_ASN1_STRING_print(WOLFSSL_BIO *bio, WOLFSSL_ASN1_STRING *str)
{
    int len = 0;

    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_print");

    /* Validate parameters. */
    if ((bio != NULL) && (str != NULL)) {
        int i;

        len = str->length;
        /* Convert all unprintable characters to '.'. */
        for (i = 0; i < len; i++) {
            if (wolfssl_unprintable_char(str->data[i])) {
                str->data[i] = '.';
            }
        }
        /* Write string to BIO. */
        if (wolfSSL_BIO_write(bio, str->data, len) != len) {
            len = 0;
        }
    }

    return len;
}
#endif /* !NO_BIO */
#endif /* !NO_ASN */

/* Get a string for the ASN.1 tag.
 *
 * @param [in] tag  ASN.1 tag.
 * @return  A string.
 */
const char* wolfSSL_ASN1_tag2str(int tag)
{
    static const char *const tag_label[31] = {
        "EOC", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING", "NULL",
        "OBJECT", "OBJECT DESCRIPTOR", "EXTERNAL", "REAL", "ENUMERATED",
        "<ASN1 11>", "UTF8STRING", "<ASN1 13>", "<ASN1 14>", "<ASN1 15>",
        "SEQUENCE", "SET", "NUMERICSTRING", "PRINTABLESTRING", "T61STRING",
        "VIDEOTEXTSTRING", "IA5STRING", "UTCTIME", "GENERALIZEDTIME",
        "GRAPHICSTRING", "VISIBLESTRING", "GENERALSTRING", "UNIVERSALSTRING",
        "<ASN1 29>", "BMPSTRING"
    };
    const char* str = "(unknown)";

    /* Clear negative flag. */
    if ((tag == WOLFSSL_V_ASN1_NEG_INTEGER) ||
            (tag == WOLFSSL_V_ASN1_NEG_ENUMERATED)) {
        tag &= ~WOLFSSL_V_ASN1_NEG;
    }
    /* Check for known basic types. */
    if ((tag >= 0) && (tag <= 30)) {
        str = tag_label[tag];
    }

    return str;
}

#ifndef NO_BIO

/* Print out ASN.1 tag for the ASN.1 STRING to the BIO.
 *
 * @param [in] bio  BIO to write to.
 * @param [in] str  ASN.1 STRING object.
 * @return  Number of characters written on success.
 * @return  0 when BIO write fails.
 */
static int wolfssl_string_print_type(WOLFSSL_BIO *bio, WOLFSSL_ASN1_STRING *str)
{
    int type_len;
    const char *tag;

    /* Get tag and string length. */
    tag = wolfSSL_ASN1_tag2str(str->type);
    type_len = (int)XSTRLEN(tag);
    /* Write tag to BIO. */
    if (wolfSSL_BIO_write(bio, tag, type_len) != type_len){
        type_len = 0;
    }
    /* Write colon after tag string. */
    else if (wolfSSL_BIO_write(bio, ":", 1) != 1) {
        type_len = 0;
    }
    else {
        /* Written colon - update count. */
        type_len++;
    }

    return type_len;
}

/* Dump hex digit representation of each string character to BIO.
 *
 * TODO: Assumes length is only one byte ie less than 128 characters long.
 *
 * @param [in] bio    BIO to write to.
 * @param [in] str    ASN.1 STRING object.
 * @param [in] asDer  Whether to write out as a DER encoding.
 * @return  Number of characters written to BIO on success.
 * @return  -1 when writing to BIO fails.
 */
static int wolfssl_asn1_string_dump_hex(WOLFSSL_BIO *bio,
    WOLFSSL_ASN1_STRING *str, int asDer)
{
    const char* hash="#";
    char hex_tmp[4];
    int str_len = 1;

    /* Write out hash character to indicate hex string. */
    if (wolfSSL_BIO_write(bio, hash, 1) != 1) {
        str_len = WOLFSSL_FATAL_ERROR;
    }
    else {
        /* Check if we are to write out DER header. */
        if (asDer) {
            /* Encode tag and length as hex into temporary. */
            ByteToHexStr((byte)str->type, &hex_tmp[0]);
            ByteToHexStr((byte)str->length, &hex_tmp[2]);
            /* Update count of written characters: tag and length. */
            str_len += 4;
            /* Write out tag and length as hex digits. */
            if (wolfSSL_BIO_write(bio, hex_tmp, 4) != 4) {
                str_len = WOLFSSL_FATAL_ERROR;
            }
        }
    }

    if (str_len != -1) {
        char* p;
        char* end;

        /* Calculate end of string. */
        end = str->data + str->length - 1;
        for (p = str->data; p <= end; p++) {
            /* Encode string character as hex into temporary. */
            ByteToHexStr((byte)*p, hex_tmp);
            /* Update count of written characters. */
            str_len += 2;
            /* Write out character as hex digites. */
            if (wolfSSL_BIO_write(bio, hex_tmp, 2) != 2) {
                str_len = WOLFSSL_FATAL_ERROR;
                break;
            }
        }
    }

    return str_len;
}

/* Check whether character needs to be escaped.
 *
 * @param [in] c    Character to check for.
 * @param [in] str  String to check.
 * @return  1 when character found.
 * @return  0 when character not found.
 */
static int wolfssl_check_esc_char(char c)
{
    int ret = 0;
    const char esc_ch[] = "+;<>\\";
    const char* p = esc_ch;

    /* Check if character matches any of those needing escaping. */
    for (; (*p) != '\0'; p++) {
        /* Check if character matches escape character. */
        if (c == (*p)) {
            ret = 1;
            break;
        }
    }

    return ret;
}

/* Print out string, with escaping for special characters, to BIO.
 *
 * @param [in] bio  BIO to write to.
 * @param [in] str  ASN.1 STRING object.
 * @return  Number of characters written to BIO on success.
 * @return  -1 when writing to BIO fails.
 */
static int wolfssl_asn1_string_print_esc_2253(WOLFSSL_BIO *bio,
    WOLFSSL_ASN1_STRING *str)
{
    char* p;
    int str_len = 0;

    /* Write all of string character by character. */
    for (p = str->data; (*p) != '\0'; p++) {
        /* Check if character needs escaping. */
        if (wolfssl_check_esc_char(*p)){
            /* Update count of written characters. */
            str_len++;
            /* Write out escaping character. */
            if (wolfSSL_BIO_write(bio,"\\", 1) != 1) {
                str_len = WOLFSSL_FATAL_ERROR;
                break;
            }
        }
        /* Update count of written characters. */
        str_len++;
        /* Write out character. */
        if (wolfSSL_BIO_write(bio, p, 1) != 1) {
            str_len = WOLFSSL_FATAL_ERROR;
            break;
        }
    }

    return str_len;
}

/* Extended print ASN.1 STRING to BIO.
 *
 * @param [in] bio    BIO to print to.
 * @param [in] str    ASN.1 STRING to print.
 * @param [in] flags  Flags describing output format.
 * @return  Length of string written on success.
 * @return  0 when bio or str is NULL.
 * @return  0 when writing to BIO fails.
 */
int wolfSSL_ASN1_STRING_print_ex(WOLFSSL_BIO *bio, WOLFSSL_ASN1_STRING *str,
    unsigned long flags)
{
    int err = 0;
    int str_len = -1;
    int type_len = 0;

    WOLFSSL_ENTER("wolfSSL_ASN1_STRING_PRINT_ex");

    /* Validate parameters. */
    if ((bio == NULL) || (str == NULL)) {
        err = 1;
    }
    /* Check if ASN.1 type is to be printed. */
    if ((!err) && (flags & WOLFSSL_ASN1_STRFLGS_SHOW_TYPE)) {
        /* Print type and colon to BIO. */
        type_len = wolfssl_string_print_type(bio, str);
        if (type_len == 0) {
            err = 1;
        }
    }

    if (!err) {
        if (flags & WOLFSSL_ASN1_STRFLGS_DUMP_ALL) {
            /* Dump hex. */
            str_len = wolfssl_asn1_string_dump_hex(bio, str,
                flags & WOLFSSL_ASN1_STRFLGS_DUMP_DER);
        }
        else if (flags & WOLFSSL_ASN1_STRFLGS_ESC_2253) {
            /* Print out string with escaping. */
            str_len = wolfssl_asn1_string_print_esc_2253(bio, str);
        }
        else {
            /* Get number of characters to write. */
            str_len = str->length;
            /* Print out string as is. */
            if (wolfSSL_BIO_write(bio, str->data, str_len) != str_len) {
                err = 1;
            }
        }
    }

    if ((!err) && (str_len >= 0)) {
        /* Include any characters written for type. */
        str_len += type_len;
    }
    else {
        str_len = 0;
    }

    return str_len;
}

#endif /* !NO_BIO */

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * ASN1_GENERALIZEDTIME APIs
 ******************************************************************************/

#ifdef OPENSSL_EXTRA

/* Free the static ASN.1 GENERALIZED TIME object.
 *
 * Not an OpenSSL compatibility API.
 *
 * @param [in] asn1Time  ASN.1 GENERALIZED TIME object.
 */
void wolfSSL_ASN1_GENERALIZEDTIME_free(WOLFSSL_ASN1_TIME* asn1Time)
{
    WOLFSSL_ENTER("wolfSSL_ASN1_GENERALIZEDTIME_free");
    XFREE(asn1Time, NULL, DYNAMIC_TYPE_OPENSSL);
}

#ifndef NO_BIO
/* Return the month as a string.
 *
 * Assumes n is '01'-'12'.
 *
 * @param [in] n  The number of the month as a two characters (1 based).
 * @return  Month as a string.
 */
static WC_INLINE const char* MonthStr(const char* n)
{
    static const char monthStr[12][4] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const char* month = "BAD";
    int i;

    i = (n[0] - '0') * 10 + (n[1] - '0') - 1;
    /* Convert string to number and index table. */
    if ((i >= 0) && (i < 12)) {
        month = monthStr[i];
    }

    return month;
}

/* Print an ASN.1 GENERALIZED TIME to a BIO.
 *
 * @param [in] bio      BIO to write to.
 * @param [in] asnTime  ASN.1 GENERALIZED TIME object.
 * @return  1 on success.
 * @return  0 when ASN.1 GENERALIZED TIME type is invalid.
 * @return  0 when writing to BIO fails.
 * @return  BAD_FUNC_ARG when bio or asnTime is NULL.
 */
int wolfSSL_ASN1_GENERALIZEDTIME_print(WOLFSSL_BIO* bio,
    const WOLFSSL_ASN1_GENERALIZEDTIME* asnTime)
{
    int ret = 1;
    const char* p = NULL;
    WOLFSSL_ENTER("wolfSSL_ASN1_GENERALIZEDTIME_print");

    /* Validate parameters. */
    if ((bio == NULL) || (asnTime == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check type is GENERALIZED TIME. */
    if ((ret == 1) && (asnTime->type != WOLFSSL_V_ASN1_GENERALIZEDTIME)) {
        WOLFSSL_MSG("Error, not GENERALIZED_TIME");
        ret = 0;
    }
    if (ret == 1) {
        /* Get the string. */
        p = (const char *)(asnTime->data);

        /* Print month as a 3 letter string. */
        if (wolfSSL_BIO_write(bio, MonthStr(p + 4), 3) != 3) {
            ret = 0;
        }
    }
    /* Print space separator. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, " ", 1) != 1)) {
        ret = 0;
    }

    /* Print day. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, p + 6, 2) != 2)) {
        ret = 0;
    }
    /* Print space separator. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, " ", 1) != 1)) {
        ret = 0;
    }

    /* Print hour. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, p + 8, 2) != 2)) {
        ret = 0;
    }
    /* Print time separator - colon. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, ":", 1) != 1)) {
        ret = 0;
    }

    /* Print minutes. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, p + 10, 2) != 2)) {
        ret = 0;
    }
    /* Print time separator - colon. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, ":", 1) != 1)) {
        ret = 0;
    }

    /* Print seconds. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, p + 12, 2) != 2)) {
        ret = 0;
    }
    /* Print space separator. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, " ", 1) != 1)) {
        ret = 0;
    }
    /* Print year. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, p, 4) != 4)) {
        ret = 0;
    }

    return ret;
}
#endif /* !NO_BIO */

#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * ASN1_TIME APIs
 ******************************************************************************/

#ifdef OPENSSL_EXTRA
/* Allocate a new ASN.1 TIME object.
 *
 * @return  New empty ASN.1 TIME object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_new(void)
{
    WOLFSSL_ASN1_TIME* ret;

    /* Allocate a new ASN.1 TYPE object. */
    ret = (WOLFSSL_ASN1_TIME*)XMALLOC(sizeof(WOLFSSL_ASN1_TIME), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (ret != NULL) {
        /* Clear out fields. */
        XMEMSET(ret, 0, sizeof(WOLFSSL_ASN1_TIME));
    }

    return ret;
}

/* Dispose of ASN.1 TIME object.
 *
 * @param [in, out] t  ASN.1 TIME object.
 */
void wolfSSL_ASN1_TIME_free(WOLFSSL_ASN1_TIME* t)
{
    /* Dispose of ASN.1 TIME object. */
    XFREE(t, NULL, DYNAMIC_TYPE_OPENSSL);
}

#ifndef NO_WOLFSSL_STUB
/* Set the Unix time GMT into ASN.1 TIME object.
 *
 * Not implemented.
 *
 * @param [in, out] a   ASN.1 TIME object.
 * @param [in]      t   Unix time GMT.
 * @return  An ASN.1 TIME object.
 */
WOLFSSL_ASN1_TIME *wolfSSL_ASN1_TIME_set(WOLFSSL_ASN1_TIME *a, time_t t)
{
    WOLFSSL_STUB("wolfSSL_ASN1_TIME_set");
    (void)a;
    (void)t;
    return a;
}
#endif /* !NO_WOLFSSL_STUB */

#ifndef NO_ASN_TIME
/* Convert time to Unix time (GMT).
 *
 * @param [in] sec     Second in minute. 0-59.
 * @param [in] minute  Minute in hour. 0-59.
 * @param [in] hour    Hour in day. 0-23.
 * @param [in] mday    Day of month. 1-31.
 * @param [in] mon     Month of year. 0-11
 * @param [in] year    Year including century. ie: 1991, 2023, 2048.
 * @return  Seconds since 00:00:00 01/01/1970 for the time passed in.
 */
static long long wolfssl_time_to_unix_time(int sec, int minute, int hour,
    int mday, int mon, int year)
{
    /* Number of cumulative days from the previous months, starting from
     * beginning of January. */
    static const int monthDaysCumulative [12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    int leapDays = year;

    /* Leap day at end of February. */
    if (mon <= 1) {
        --leapDays;
    }
    /* Calculate leap days. */
    leapDays = leapDays / 4 - leapDays / 100 + leapDays / 400 - 1969 / 4 +
               1969 / 100 - 1969 / 400;

    /* Calculate number of seconds. */
    return ((((long long) (year - 1970) * 365 + leapDays +
           monthDaysCumulative[mon] + mday - 1) * 24 + hour) * 60 + minute) *
           60 + sec;
}

/* Convert ASN.1 TIME object to Unix time (GMT).
 *
 * @param [in]  t     ASN.1 TIME object.
 * @param [out] secs  Number of seconds since 00:00:00 01/01/1970.
 * @return  1 on success.
 * @return  0 when conversion of time fails.
 */
static int wolfssl_asn1_time_to_secs(const WOLFSSL_ASN1_TIME* t,
    long long* secs)
{
    int ret = 1;
    struct tm tm_s;
    struct tm *tmGmt = &tm_s;

    /* Convert ASN.1 TIME to broken-down time. NULL treated as current time. */
    ret = wolfSSL_ASN1_TIME_to_tm(t, tmGmt);
    if (ret != 1) {
        WOLFSSL_MSG("Failed to convert from time to struct tm.");
    }
    else {
        /* We use wolfssl_time_to_unix_time here instead of XMKTIME to avoid the
         * Year 2038 problem on platforms where time_t is 32 bits. struct tm
         * stores the year as years since 1900, so we add 1900 to the year. */
        *secs = wolfssl_time_to_unix_time(tmGmt->tm_sec, tmGmt->tm_min,
            tmGmt->tm_hour, tmGmt->tm_mday, tmGmt->tm_mon,
            tmGmt->tm_year + 1900);
    }

    return ret;
}

/* Calculate difference in time of two ASN.1 TIME objects.
 *
 * @param [out] days  Number of whole days between from and to.
 * @param [out] secs  Number of seconds less than a day between from and to.
 * @param [in]  from  ASN.1 TIME object as start time.
 * @param [in]  to    ASN.1 TIME object as end time.
 * @return  1 on success.
 * @return  0 when conversion of time fails.
 */
int wolfSSL_ASN1_TIME_diff(int *days, int *secs, const WOLFSSL_ASN1_TIME *from,
    const WOLFSSL_ASN1_TIME *to)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_diff");

    if ((from == NULL) && (to == NULL)) {
        if (days != NULL) {
            *days = 0;
        }
        if (secs != NULL) {
            *secs = 0;
        }
    }
    else {
        const long long SECS_PER_DAY = 24 * 60 * 60;
        long long fromSecs;
        long long toSecs = 0;

        ret = wolfssl_asn1_time_to_secs(from, &fromSecs);
        if (ret == 1) {
            ret = wolfssl_asn1_time_to_secs(to, &toSecs);
        }
        if (ret == 1) {
            long long diffSecs = toSecs - fromSecs;
            if (days != NULL) {
                *days = (int) (diffSecs / SECS_PER_DAY);
            }
            if (secs != NULL) {
                *secs = (int) (diffSecs -
                        ((long long)(diffSecs / SECS_PER_DAY) * SECS_PER_DAY));
            }
        }
    }

    return ret;
}

/* Compare two ASN.1 TIME objects by comparing time value.
 *
 * @param [in] a  First ASN.1 TIME object.
 * @param [in] b  Second ASN.1 TIME object.
 * @return Negative value when a is less than b.
 * @return 0 when a equals b.
 * @return Positive value when a is greater than b.
 * @return -2 when a or b is invalid.
 */
int wolfSSL_ASN1_TIME_compare(const WOLFSSL_ASN1_TIME *a,
    const WOLFSSL_ASN1_TIME *b)
{
    int ret;
    int days;
    int secs;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_compare");

    /* Calculate difference in time between a and b. */
    if (wolfSSL_ASN1_TIME_diff(&days, &secs, a, b) != 1) {
        WOLFSSL_MSG("Failed to get time difference.");
        ret = -2;
    }
    else if (days == 0 && secs == 0) {
        /* a and b are the same time. */
        ret = 0;
    }
    else if (days >= 0 && secs >= 0) {
        /* a is before b. */
        ret = -1;
    }
    /* Assume wolfSSL_ASN1_TIME_diff creates coherent values. */
    else {
        ret = 1;
    }

    WOLFSSL_LEAVE("wolfSSL_ASN1_TIME_compare", ret);

    return ret;
}

#if !defined(USER_TIME) && !defined(TIME_OVERRIDES)
/* Adjust the time into an ASN.1 TIME object.
 *
 * @param [in] a           ASN.1 TIME object. May be NULL.
 * @param [in] t           Time to offset.
 * @param [in] offset_day  Number of days to offset. May be negative.
 * @param [in] offset_sec  Number of seconds to offset. May be negative.
 * @return  ASN.1 TIME object on success.
 * @return  NULL when formatting time fails.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_adj(WOLFSSL_ASN1_TIME* a, time_t t,
    int offset_day, long offset_sec)
{
    WOLFSSL_ASN1_TIME* ret = NULL;
    const time_t sec_per_day = 24*60*60;
    int time_get;
    char time_str[MAX_TIME_STRING_SZ];
    time_t offset_day_sec = offset_day * sec_per_day;
    time_t t_adj          = t + offset_day_sec + offset_sec;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_adj");

    /* Get time string as either UTC or GeneralizedTime. */
    time_get = GetFormattedTime(&t_adj, (byte*)time_str, MAX_TIME_STRING_SZ);
    if (time_get > 0) {
        ret = a;
        if (ret == NULL) {
            ret = wolfSSL_ASN1_TIME_new();
        }
        /* Set the string into the ASN.1 TIME object. */
        if ((wolfSSL_ASN1_TIME_set_string(ret, time_str) != 1) && (ret != a)) {
            wolfSSL_ASN1_TIME_free(ret);
            ret = NULL;
        }
    }

    return ret;
}
#endif /* !USER_TIME && !TIME_OVERRIDES */
#endif /* !NO_ASN_TIME */

/* Get the length of the ASN.1 TIME data.
 *
 * Not an OpenSSL function - ASN1_TIME is not opaque.
 *
 * @param [in] t  ASN.1 TIME object.
 * @return  Length of data on success.
 * @return  0 when t is NULL or no time set.
 */
int wolfSSL_ASN1_TIME_get_length(const WOLFSSL_ASN1_TIME *t)
{
    int len = 0;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_get_length");

    if (t != NULL) {
        len = t->length;
    }

    return len;
}

/* Get the data from the ASN.1 TIME object.
 *
 * Not an OpenSSL function - ASN1_TIME is not opaque.
 *
 * @param [in] t  ASN.1 TIME object.
 * @return  Data buffer on success.
 * @return  NULL when t is NULL.
 */
unsigned char* wolfSSL_ASN1_TIME_get_data(const WOLFSSL_ASN1_TIME *t)
{
    unsigned char* data = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_get_data");

    if (t != NULL) {
        data = (unsigned char*)t->data;
    }

    return data;
}

#ifndef NO_ASN_TIME
/* Check format of string in ASN.1 TIME object.
 *
 * @param [in] a  ASN.1 TIME object.
 * @return  1 on success.
 * @return  0 when format invalid.
 */
int wolfSSL_ASN1_TIME_check(const WOLFSSL_ASN1_TIME* a)
{
    int ret = WOLFSSL_SUCCESS;
    char buf[MAX_TIME_STRING_SZ];

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_check");

    /* If can convert to human readable then format good. */
    if (wolfSSL_ASN1_TIME_to_string((WOLFSSL_ASN1_TIME*)a, buf,
            MAX_TIME_STRING_SZ) == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    return ret;
}
#endif /* !NO_ASN_TIME */

/* Set the time as a string into ASN.1 TIME object.
 *
 * When t is NULL, str is checked only.
 *
 * @param [in, out] t    ASN.1 TIME object.
 * @param [in]      str  Time as a string.
 * @return  1 on success.
 * @return  0 when str is NULL.
 * @return  0 when str is not formatted correctly.
 */
int wolfSSL_ASN1_TIME_set_string(WOLFSSL_ASN1_TIME *t, const char *str)
{
    int ret = WOLFSSL_SUCCESS;
    int slen = 0;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_set_string");

    if (str == NULL) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }
    if (ret == WOLFSSL_SUCCESS) {
        /* Get length of string including NUL terminator. */
        slen = (int)XSTRLEN(str) + 1;
        if (slen > CTC_DATE_SIZE) {
            WOLFSSL_MSG("Date string too long");
            ret = WOLFSSL_FAILURE;
        }
    }
    if ((ret == WOLFSSL_SUCCESS) && (t != NULL)) {
        /* Copy in string including NUL terminator. */
        XMEMCPY(t->data, str, (size_t)slen);
        /* Do not include NUL terminator in length. */
        t->length = slen - 1;
        /* Set ASN.1 type based on string length. */
        t->type = ((slen == ASN_UTC_TIME_SIZE) ? WOLFSSL_V_ASN1_UTCTIME :
            WOLFSSL_V_ASN1_GENERALIZEDTIME);
    }

    return ret;
}

#ifndef NO_ASN_TIME
int wolfSSL_ASN1_TIME_set_string_X509(WOLFSSL_ASN1_TIME *t, const char *str)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_set_string_X509");

    if (t == NULL)
        ret = WOLFSSL_FAILURE;
    if (ret == WOLFSSL_SUCCESS)
        ret = wolfSSL_ASN1_TIME_set_string(t, str);
    if (ret == WOLFSSL_SUCCESS)
        ret = wolfSSL_ASN1_TIME_check(t);
    return ret;
}
#endif /* !NO_ASN_TIME */

/* Convert ASN.1 TIME object to ASN.1 GENERALIZED TIME object.
 *
 * @param [in]      t    ASN.1 TIME object.
 * @param [in, out] out  ASN.1 GENERALIZED TIME object.
 * @return  ASN.1 GENERALIZED TIME object on success.
 * @return  NULL when t is NULL or t has wrong ASN.1 type.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_to_generalizedtime(WOLFSSL_ASN1_TIME *t,
    WOLFSSL_ASN1_TIME **out)
{
    WOLFSSL_ASN1_TIME *ret = NULL;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_to_generalizedtime");

    /* Validate parameters. */
    if (t == NULL) {
        WOLFSSL_MSG("Invalid ASN_TIME value");
    }
    /* Ensure ASN.1 type is one that is supported. */
    else if ((t->type != WOLFSSL_V_ASN1_UTCTIME) &&
             (t->type != WOLFSSL_V_ASN1_GENERALIZEDTIME)) {
        WOLFSSL_MSG("Invalid ASN_TIME type.");
    }
    /* Check for ASN.1 GENERALIZED TIME object being passed in. */
    else if ((out != NULL) && (*out != NULL)) {
        /* Copy into the passed in object. */
        ret = *out;
    }
    else {
        /* Create a new ASN.1 GENERALIZED TIME object. */
        ret = wolfSSL_ASN1_TIME_new();
        if (ret == NULL) {
            WOLFSSL_MSG("memory alloc failed.");
        }
    }

    if (ret != NULL) {
        /* Set the ASN.1 type and length of string. */
        ret->type = WOLFSSL_V_ASN1_GENERALIZEDTIME;

        if (t->type == WOLFSSL_V_ASN1_GENERALIZEDTIME) {
            ret->length = ASN_GENERALIZED_TIME_SIZE;

            /* Just copy as data already appropriately formatted. */
            XMEMCPY(ret->data, t->data, ASN_GENERALIZED_TIME_SIZE);
        }
        else {
            /* Convert UTC TIME to GENERALIZED TIME. */
            ret->length = t->length + 2; /* Add two extra year digits */

            if (t->data[0] >= '5') {
                /* >= 50 is 1900s.  */
                ret->data[0] = '1'; ret->data[1] = '9';
            }
            else {
                /* < 50 is 2000s.  */
                ret->data[0] = '2'; ret->data[1] = '0';
            }
            /* Append rest of the data as it is the same. */
            XMEMCPY(&ret->data[2], t->data, t->length);
        }

        /* Check for pointer to return result through. */
        if (out != NULL) {
            *out = ret;
        }
    }

    return ret;
}

#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && !defined(TIME_OVERRIDES)
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_UTCTIME_set(WOLFSSL_ASN1_TIME *s, time_t t)
{
    WOLFSSL_ASN1_TIME* ret = s;

    WOLFSSL_ENTER("wolfSSL_ASN1_UTCTIME_set");

    if (ret == NULL) {
        ret = wolfSSL_ASN1_TIME_new();
        if (ret == NULL)
            return NULL;
    }

    ret->length = GetFormattedTime(&t, ret->data, sizeof(ret->data));
    if (ret->length + 1 != ASN_UTC_TIME_SIZE) {
        /* Either snprintf error or t can't be represented in UTC format */
        if (ret != s)
            wolfSSL_ASN1_TIME_free(ret);
        ret = NULL;
    }
    else {
        ret->type = WOLFSSL_V_ASN1_UTCTIME;
    }

    return ret;
}
#endif /* !USER_TIME && !TIME_OVERRIDES */
#endif /* OPENSSL_EXTRA */

#if !defined(NO_ASN_TIME) && \
    (defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(OPENSSL_EXTRA))
/* Get string from ASN.1 TIME object.
 *
 * Not an OpenSSL compatibility API.
 *
 * @param [in]      t    ASN.1 TIME object.
 * @param [in, out] buf  Buffer to put string in.
 * @param [in]      len  Length of buffer in bytes.
 * @return  buf on success.
 * @return  NULL when t or buf is NULL, or len is less than 5.
 * @return  NULL when ASN.1 TIME length is larger than len.
 * @return  NULL when internal time format not valid.
 */
char* wolfSSL_ASN1_TIME_to_string(WOLFSSL_ASN1_TIME* t, char* buf, int len)
{
    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_to_string");

    /* Validate parameters. */
    if ((t == NULL) || (buf == NULL) || (len < 5)) {
        WOLFSSL_MSG("Bad argument");
        buf = NULL;
    }

    /* Check internal length against passed in length. */
    if ((buf != NULL) && (t->length > len)) {
        WOLFSSL_MSG("Length of date is longer then buffer");
        buf = NULL;
    }

    /* Get time as human readable string. */
    if ((buf != NULL) && !GetTimeString(t->data, t->type, buf, len,
           t->length)) {
        buf = NULL;
    }

    return buf;
}

/* Number of characters in a UTC TIME string. */
#define UTCTIME_LEN     13

/* Get year from UTC TIME string.
 *
 * @param [in]  str   UTC TIME string.
 * @param [in]  len   Length of string in bytes.
 * @param [out] year  Year as extracted from string.
 * @return  1 on success.
 * @return  0 when length is too short for a UTC TIME.
 * @return  0 when not ZULU time.
 */
static int wolfssl_utctime_year(const unsigned char* str, int len, int* year)
{
    int ret = 1;

    /* Check minimal length for UTC TIME. */
    if (len < UTCTIME_LEN) {
        WOLFSSL_MSG("WOLFSSL_ASN1_TIME buffer length is invalid.");
        ret = 0;
    }
    /* Only support ZULU time. */
    if ((ret == 1) && (str[UTCTIME_LEN - 1] != 'Z')) {
        WOLFSSL_MSG("Expecting UTC time.");
        ret = 0;
    }

    if (ret == 1) {
        if ((str[0] < '0') || (str[0] > '9') ||
            (str[1] < '0') || (str[1] > '9')) {
            WOLFSSL_MSG("Invalid characters in UTC year.");
            ret = 0;
        }
    }

    if (ret == 1) {
        int tm_year;
        /* 2-digit year. */
        tm_year =  (str[0] - '0') * 10;
        tm_year +=  str[1] - '0';
        /* Check for year being in the 2000s. */
        if (tm_year < 50) {
            tm_year += 100;
        }
        *year = tm_year;
    }

    return ret;
}

/* Number of characters in a GENERALIZED TIME string. */
#define GENTIME_LEN     15

/* Get year from GENERALIZED TIME string.
 *
 * @param [in]  str   GENERALIZED TIME string.
 * @param [in]  len   Length of string in bytes.
 * @param [out] year  Year as extracted from string.
 * @return  1 on success.
 * @return  0 when length is too short for a GENERALIZED TIME.
 * @return  0 when not ZULU time.
 */
static int wolfssl_gentime_year(const unsigned char* str, int len, int* year)
{
    int ret = 1;

    /* Check minimal length for GENERALIZED TIME. */
    if (len < GENTIME_LEN) {
        WOLFSSL_MSG("WOLFSSL_ASN1_TIME buffer length is invalid.");
        ret = 0;
    }
    if ((ret == 1) && (str[GENTIME_LEN - 1] != 'Z')) {
        WOLFSSL_MSG("Expecting Generalized time.");
        ret = 0;
    }

    if (ret == 1) {
        if ((str[0] < '0') || (str[0] > '9') ||
            (str[1] < '0') || (str[1] > '9') ||
            (str[2] < '0') || (str[2] > '9') ||
            (str[3] < '0') || (str[3] > '9')) {
            WOLFSSL_MSG("Invalid characters in generalized year.");
            ret = 0;
        }
    }

    if (ret == 1) {
        int tm_year;
        /* 4-digit year. */
        tm_year =  (str[0] - '0') * 1000;
        tm_year += (str[1] - '0') * 100;
        tm_year += (str[2] - '0') * 10;
        tm_year +=  str[3] - '0';
        /* Only need value to be years since 1900. */
        tm_year -= 1900;
        *year = tm_year;
    }

    return ret;
}

/* Convert an ASN.1 TIME to a struct tm.
 *
 * @param [in] asnTime  ASN.1 TIME object.
 * @param [in] tm       Broken-down time. Must be non-NULL.
 * @return  1 on success.
 * @return  0 when string format is invalid.
 */
static int wolfssl_asn1_time_to_tm(const WOLFSSL_ASN1_TIME* asnTime,
    struct tm* tm)
{
    int ret = 1;
    const unsigned char* asn1TimeBuf;
    int asn1TimeBufLen;
    int i = 0;
    /* Parse into a local struct so the caller's tm is only written on
     * success. Avoids leaving a partially-populated struct behind when
     * the input fails validation. */
    struct tm localTm;

    XMEMSET(&localTm, 0, sizeof(localTm));

    /* Get the string buffer - fixed array, can't fail. */
    asn1TimeBuf = wolfSSL_ASN1_TIME_get_data(asnTime);
    /* Get the length of the string. */
    asn1TimeBufLen = wolfSSL_ASN1_TIME_get_length(asnTime);
    if (asn1TimeBufLen <= 0) {
        WOLFSSL_MSG("Failed to get WOLFSSL_ASN1_TIME buffer length.");
        ret = 0;
    }
    if (ret == 1) {
        if (asnTime->type == WOLFSSL_V_ASN1_UTCTIME) {
            /* Get year from UTC TIME string. */
            int tm_year;
            if ((ret = wolfssl_utctime_year(asn1TimeBuf, asn1TimeBufLen,
                    &tm_year)) == 1) {
                localTm.tm_year = tm_year;
                /* Month starts after year - 2 characters. */
                i = 2;
            }
        }
        else if (asnTime->type == WOLFSSL_V_ASN1_GENERALIZEDTIME) {
            /* Get year from GENERALIZED TIME string. */
            int tm_year;
            if ((ret = wolfssl_gentime_year(asn1TimeBuf, asn1TimeBufLen,
                    &tm_year)) == 1) {
                localTm.tm_year = tm_year;
                /* Month starts after year - 4 characters. */
                i = 4;
            }
        }
        else {
            /* No other time formats known. */
            WOLFSSL_MSG("asnTime->type is invalid.");
            ret = 0;
        }
    }

    if (ret == 1) {
        int j;
        /* Validate 10 digits: MMDDHHMMSS. Length was already checked
         * (>= UTCTIME_LEN or >= GENTIME_LEN), so i+10 is in range. */
        for (j = i; j < i + 10; j++) {
            if (asn1TimeBuf[j] < '0' || asn1TimeBuf[j] > '9') {
                WOLFSSL_MSG("Non-digit in ASN.1 TIME.");
                ret = 0;
                break;
            }
        }
    }

    if (ret == 1) {
        /* Fill in rest of broken-down time from string. */
        /* January is 0 not 1 */
        localTm.tm_mon   = (asn1TimeBuf[i] - '0') * 10; i++;
        localTm.tm_mon  += (asn1TimeBuf[i] - '0') - 1;  i++;
        localTm.tm_mday  = (asn1TimeBuf[i] - '0') * 10; i++;
        localTm.tm_mday += (asn1TimeBuf[i] - '0');      i++;
        localTm.tm_hour  = (asn1TimeBuf[i] - '0') * 10; i++;
        localTm.tm_hour += (asn1TimeBuf[i] - '0');      i++;
        localTm.tm_min   = (asn1TimeBuf[i] - '0') * 10; i++;
        localTm.tm_min  += (asn1TimeBuf[i] - '0');      i++;
        localTm.tm_sec   = (asn1TimeBuf[i] - '0') * 10; i++;
        localTm.tm_sec  += (asn1TimeBuf[i] - '0');
    }

    if (ret == 1) {
        /* Range-check broken-down fields. ValidateGmtime returns 0 on
         * success. */
        if (ValidateGmtime(&localTm)) {
            WOLFSSL_MSG("Out-of-range field in ASN.1 TIME.");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Publish to caller. */
        XMEMCPY(tm, &localTm, sizeof(*tm));
    #ifdef XMKTIME
        /* XMKTIME may set tm_isdst/tm_gmtoff on localTm; call after the
         * copy so those fields stay zero in the caller's tm. */
        XMKTIME(&localTm);
        tm->tm_wday = localTm.tm_wday;
        tm->tm_yday = localTm.tm_yday;
    #endif
    }

    return ret;
}

/* Get the current time into a broken-down time.
 *
 * @param [out] tm  Broken-time time.
 * @return  1 on success.
 * @return  0 when tm is NULL.
 * @return  0 when get current time fails.
 * @return  0 when converting Unix time to broken-down time fails.
 */
static int wolfssl_get_current_time_tm(struct tm* tm)
{
    int ret = 1;
    time_t currentTime;
    struct tm *tmpTs;
#if defined(NEED_TMP_TIME)
    /* for use with gmtime_r */
    struct tm tmpTimeStorage;
    tmpTs = &tmpTimeStorage;
#else
    tmpTs = NULL;
#endif
    (void)tmpTs;

    /* Must have a pointer to return result into. */
    if (tm == NULL) {
        WOLFSSL_MSG("asnTime and tm are both NULL");
        ret = 0;
    }
    if (ret == 1) {
        /* Get current Unix Time GMT. */
        currentTime = wc_Time(0);
        if (currentTime <= 0) {
            WOLFSSL_MSG("Failed to get current time.");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Convert Unix Time GMT into broken-down time. */
        tmpTs = XGMTIME(&currentTime, tmpTs);
        if (tmpTs == NULL) {
            WOLFSSL_MSG("Failed to convert current time to UTC.");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Copy from the structure returned into parameter. */
        XMEMCPY(tm, tmpTs, sizeof(*tm));
    }

    return ret;
}

/* Convert ASN.1 TIME object's time into broken-down representation.
 *
 * Internal time string is checked when tm is NULL.
 *
 * @param [in]  asnTime  ASN.1 TIME object.
 * @param [out] tm       Broken-down time.
 * @return  1 on success.
 * @return  0 when asnTime is NULL and tm is NULL.
 * @return  0 getting current time fails.
 * @return  0 when internal time string is invalid.
 */
int wolfSSL_ASN1_TIME_to_tm(const WOLFSSL_ASN1_TIME* asnTime, struct tm* tm)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_to_tm");

    /* If asnTime is NULL, then the current time is converted. */
    if (asnTime == NULL) {
        ret = wolfssl_get_current_time_tm(tm);
    }
    /* If tm is NULL this function performs a format check on asnTime only. */
    else if (tm == NULL) {
        ret = wolfSSL_ASN1_TIME_check(asnTime);
    }
    else {
        /* Convert ASN.1 TIME to broken-down time. */
        ret = wolfssl_asn1_time_to_tm(asnTime, tm);
    }

    return ret;
}

#ifndef NO_BIO
/* Print the ASN.1 TIME object as a string to BIO.
 *
 * @param [in] bio      BIO to write to.
 * @param [in] asnTime  ASN.1 TIME object.
 * @return  1 on success.
 * @return  0 when bio or asnTime is NULL.
 * @return  0 when creating human readable string fails.
 * @return  0 when writing to BIO fails.
 */
int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO* bio, const WOLFSSL_ASN1_TIME* asnTime)
{
    int  ret = 1;

    WOLFSSL_ENTER("wolfSSL_ASN1_TIME_print");

    /* Validate parameters. */
    if ((bio == NULL) || (asnTime == NULL)) {
        WOLFSSL_MSG("NULL function argument");
        ret = 0;
    }

    if (ret == 1) {
        char buf[MAX_TIME_STRING_SZ];
        int len;

        /* Create human readable string. */
        if (wolfSSL_ASN1_TIME_to_string((WOLFSSL_ASN1_TIME*)asnTime, buf,
                sizeof(buf)) == NULL) {
            /* Write out something anyway but return error. */
            XMEMSET(buf, 0, MAX_TIME_STRING_SZ);
            XSTRNCPY(buf, "Bad time value", sizeof(buf)-1);
            ret = 0;
        }

        /* Write out string. */
        len = (int)XSTRLEN(buf);
        if (wolfSSL_BIO_write(bio, buf, len) != len) {
            WOLFSSL_MSG("Unable to write to bio");
            ret = 0;
        }
    }

    return ret;
}
#endif /* !NO_BIO */

#endif /* !NO_ASN_TIME && (WOLFSSL_MYSQL_COMPATIBLE || OPENSSL_EXTRA) */

#if !defined(NO_ASN_TIME) && defined(OPENSSL_EXTRA)

#ifndef NO_BIO
/* Print the ASN.1 UTC TIME object as a string to BIO.
 *
 * @param [in] bio      BIO to write to.
 * @param [in] asnTime  ASN.1 UTC TIME object.
 * @return  1 on success.
 * @return  0 when bio or asnTime is NULL.
 * @return  0 when ASN.1 type is not UTC TIME.
 * @return  0 when creating human readable string fails.
 * @return  0 when writing to BIO fails.
 */
int wolfSSL_ASN1_UTCTIME_print(WOLFSSL_BIO* bio, const WOLFSSL_ASN1_UTCTIME* a)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_ASN1_UTCTIME_print");

    /* Validate parameters. */
    if ((bio == NULL) || (a == NULL)) {
        ret = 0;
    }
    /* Validate ASN.1 UTC TIME object is of type UTC_TIME. */
    if ((ret == 1) && (a->type != WOLFSSL_V_ASN1_UTCTIME)) {
        WOLFSSL_MSG("Error, not UTC_TIME");
        ret = 0;
    }

    if (ret == 1) {
        /* Use generic time printing function to do work. */
        ret = wolfSSL_ASN1_TIME_print(bio, a);
    }

    return ret;
}
#endif /* !NO_BIO */

#endif /* !NO_ASN_TIME && OPENSSL_EXTRA */

/*******************************************************************************
 * ASN1_TYPE APIs
 ******************************************************************************/

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_WPAS_SMALL)

/**
 * Allocate a new ASN.1 TYPE object.
 *
 * @return  New empty ASN.1 TYPE object on success.
 * @return  NULL when dynamic memory allocation fails.
 */
WOLFSSL_ASN1_TYPE* wolfSSL_ASN1_TYPE_new(void)
{
    WOLFSSL_ASN1_TYPE* ret;

    /* Allocate a new ASN.1 TYPE object. */
    ret = (WOLFSSL_ASN1_TYPE*)XMALLOC(sizeof(WOLFSSL_ASN1_TYPE), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (ret != NULL) {
        /* Clear out fields. */
        XMEMSET(ret, 0, sizeof(WOLFSSL_ASN1_TYPE));
    }

    return ret;
}

/* Free the ASN.1 TYPE object's value field.
 *
 * @param [in, out] at  ASN.1 TYPE object.
 */
static void wolfssl_asn1_type_free_value(WOLFSSL_ASN1_TYPE* at)
{
    switch (at->type) {
        case WOLFSSL_V_ASN1_NULL:
            break;
        case WOLFSSL_V_ASN1_OBJECT:
            wolfSSL_ASN1_OBJECT_free(at->value.object);
            break;
        case WOLFSSL_V_ASN1_UTCTIME:
        #if !defined(NO_ASN_TIME) && defined(OPENSSL_EXTRA)
            wolfSSL_ASN1_TIME_free(at->value.utctime);
        #endif
            break;
        case WOLFSSL_V_ASN1_GENERALIZEDTIME:
        #if !defined(NO_ASN_TIME) && defined(OPENSSL_EXTRA)
            wolfSSL_ASN1_TIME_free(at->value.generalizedtime);
        #endif
            break;
        case WOLFSSL_V_ASN1_UTF8STRING:
        case WOLFSSL_V_ASN1_OCTET_STRING:
        case WOLFSSL_V_ASN1_PRINTABLESTRING:
        case WOLFSSL_V_ASN1_T61STRING:
        case WOLFSSL_V_ASN1_IA5STRING:
        case WOLFSSL_V_ASN1_UNIVERSALSTRING:
        case WOLFSSL_V_ASN1_SEQUENCE:
            wolfSSL_ASN1_STRING_free(at->value.asn1_string);
            break;
        default:
            break;
    }
}

/**
 * Free ASN.1 TYPE object and its value.
 *
 * @param [in, out] at  ASN.1 TYPE object.
 */
void wolfSSL_ASN1_TYPE_free(WOLFSSL_ASN1_TYPE* at)
{
    if (at != NULL) {
        /* Dispose of value in ASN.1 TYPE object. */
        wolfssl_asn1_type_free_value(at);
    }
    /* Dispose of ASN.1 TYPE object. */
    XFREE(at, NULL, DYNAMIC_TYPE_OPENSSL);
}

#endif /* OPENSSL_ALL || OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL ||
          WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

int wolfSSL_i2d_ASN1_TYPE(WOLFSSL_ASN1_TYPE* at, unsigned char** pp)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    if (at == NULL)
        return WOLFSSL_FATAL_ERROR;

    switch (at->type) {
        case WOLFSSL_V_ASN1_NULL:
            break;
        case WOLFSSL_V_ASN1_OBJECT:
            ret = wolfSSL_i2d_ASN1_OBJECT(at->value.object, pp);
            break;
        case WOLFSSL_V_ASN1_UTF8STRING:
            ret = wolfSSL_i2d_ASN1_UTF8STRING(at->value.utf8string, pp);
            break;
        case WOLFSSL_V_ASN1_GENERALIZEDTIME:
            ret = wolfSSL_i2d_ASN1_GENERALSTRING(at->value.utf8string, pp);
            break;
        case WOLFSSL_V_ASN1_SEQUENCE:
            ret = wolfSSL_i2d_ASN1_SEQUENCE(at->value.sequence, pp);
            break;
        case WOLFSSL_V_ASN1_UTCTIME:
        case WOLFSSL_V_ASN1_PRINTABLESTRING:
        case WOLFSSL_V_ASN1_T61STRING:
        case WOLFSSL_V_ASN1_IA5STRING:
        case WOLFSSL_V_ASN1_UNIVERSALSTRING:
        default:
            WOLFSSL_MSG("asn1 i2d type not supported");
            break;
    }

    return ret;
}

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL) || defined(WOLFSSL_WPAS_SMALL)
/**
 * Set ASN.1 TYPE object with a type and value.
 *
 * Type of value for different types:
 *   WOLFSSL_V_ASN1_NULL            : Value should be NULL.
 *   WOLFSSL_V_ASN1_OBJECT          : WOLFSSL_ASN1_OBJECT.
 *   WOLFSSL_V_ASN1_UTCTIME         : WOLFSSL_ASN1_TIME.
 *   WOLFSSL_V_ASN1_GENERALIZEDTIME : WOLFSSL_ASN1_TIME.
 *   WOLFSSL_V_ASN1_UTF8STRING      : WOLFSSL_ASN1_STRING.
 *   WOLFSSL_V_ASN1_PRINTABLESTRING : WOLFSSL_ASN1_STRING.
 *   WOLFSSL_V_ASN1_T61STRING       : WOLFSSL_ASN1_STRING.
 *   WOLFSSL_V_ASN1_IA5STRING       : WOLFSSL_ASN1_STRING.
 *   WOLFSSL_V_ASN1_UNINVERSALSTRING: WOLFSSL_ASN1_STRING.
 *   WOLFSSL_V_ASN1_SEQUENCE        : WOLFSSL_ASN1_STRING.
 *
 * @param [in, out] a      ASN.1 TYPE object to set.
 * @param [in]      type   ASN.1 type of value.
 * @param [in]      value  Value to store.
 */
void wolfSSL_ASN1_TYPE_set(WOLFSSL_ASN1_TYPE *a, int type, void *value)
{
    if (a != NULL) {
        switch (type) {
            case WOLFSSL_V_ASN1_NULL:
                if (value != NULL) {
                    WOLFSSL_MSG("NULL tag meant to be always empty!");
                    /* No way to return error - value will not be used. */
                }
                FALL_THROUGH;
            case WOLFSSL_V_ASN1_OBJECT:
            case WOLFSSL_V_ASN1_UTCTIME:
            case WOLFSSL_V_ASN1_GENERALIZEDTIME:
            case WOLFSSL_V_ASN1_UTF8STRING:
            case WOLFSSL_V_ASN1_OCTET_STRING:
            case WOLFSSL_V_ASN1_PRINTABLESTRING:
            case WOLFSSL_V_ASN1_T61STRING:
            case WOLFSSL_V_ASN1_IA5STRING:
            case WOLFSSL_V_ASN1_UNIVERSALSTRING:
            case WOLFSSL_V_ASN1_SEQUENCE:
                /* Dispose of any value currently set. */
                wolfssl_asn1_type_free_value(a);
                /* Assign anonymously typed input to anonymously typed field. */
                a->value.ptr = (char *)value;
                /* Set the type required. */
                a->type = type;
                break;
            default:
                WOLFSSL_MSG("Unknown or unsupported ASN1_TYPE");
                /* No way to return error. */
        }
    }
}

int wolfSSL_ASN1_TYPE_get(const WOLFSSL_ASN1_TYPE *a)
{
    if (a != NULL && (a->type == WOLFSSL_V_ASN1_BOOLEAN ||
                      a->type == WOLFSSL_V_ASN1_NULL    ||
                      a->value.ptr != NULL)) {
        return a->type;
    }
    return 0;
}

#endif /* OPENSSL_ALL || OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL ||
          WOLFSSL_WPAS_SMALL */

#endif /* !NO_ASN */

#endif /* !OPENSSL_EXTRA_NO_ASN1 */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Table of OID information: NID, OID sum, OID group and names.
 *
 * Entries of an OID group are contiguous. Lookups search the entries of one
 * group linearly, so the order of entries within a group has been changed to
 * put the most commonly used first and the legacy and rarely used last. The
 * order is not otherwise significant. Keep new entries with their group.
 */
const WOLFSSL_ObjectInfo wolfssl_object_info[] = {
#ifndef NO_CERTS
    /* oidCertExtType */
    { WC_NID_basic_constraints, BASIC_CA_OID, oidCertExtType,
      "basicConstraints", "X509v3 Basic Constraints"},
    { WC_NID_subject_alt_name, ALT_NAMES_OID, oidCertExtType, "subjectAltName",
      "X509v3 Subject Alternative Name"},
    { WC_NID_crl_distribution_points, CRL_DIST_OID, oidCertExtType,
      "crlDistributionPoints", "X509v3 CRL Distribution Points"},
    { WC_NID_info_access, AUTH_INFO_OID, oidCertExtType, "authorityInfoAccess",
      "Authority Information Access"},
    { WC_NID_authority_key_identifier, AUTH_KEY_OID, oidCertExtType,
      "authorityKeyIdentifier", "X509v3 Authority Key Identifier"},
    { WC_NID_subject_key_identifier, SUBJ_KEY_OID, oidCertExtType,
      "subjectKeyIdentifier", "X509v3 Subject Key Identifier"},
    { WC_NID_key_usage, KEY_USAGE_OID, oidCertExtType, "keyUsage",
      "X509v3 Key Usage"},
    { WC_NID_inhibit_any_policy, INHIBIT_ANY_OID, oidCertExtType,
      "inhibitAnyPolicy", "X509v3 Inhibit Any Policy"},
    { WC_NID_ext_key_usage, EXT_KEY_USAGE_OID, oidCertExtType,
      "extendedKeyUsage", "X509v3 Extended Key Usage"},
    { WC_NID_name_constraints, NAME_CONS_OID, oidCertExtType,
      "nameConstraints", "X509v3 Name Constraints"},
    { WC_NID_certificate_policies, CERT_POLICY_OID, oidCertExtType,
      "certificatePolicies", "X509v3 Certificate Policies"},
#if defined(WOLFSSL_APACHE_HTTPD) && defined(OPENSSL_EXTRA)
    /* "1.3.6.1.4.1.311.20.2.3" */
    { WC_NID_ms_upn, WOLFSSL_MS_UPN_SUM, oidCertExtType, WOLFSSL_SN_MS_UPN,
      WOLFSSL_LN_MS_UPN },
#endif

    /* oidCertAuthInfoType */
    { WC_NID_ad_OCSP, AIA_OCSP_OID, oidCertAuthInfoType, "OCSP",
      "OCSP"},
    { WC_NID_ad_ca_issuers, AIA_CA_ISSUER_OID, oidCertAuthInfoType,
      "caIssuers", "CA Issuers"},

    /* oidCertPolicyType */
    { WC_NID_any_policy, CP_ANY_OID, oidCertPolicyType, "anyPolicy",
      "X509v3 Any Policy"},

    /* oidCertAltNameType */
    { WC_NID_hw_name_oid, HW_NAME_OID, oidCertAltNameType, "Hardware name",""},

    /* oidCertKeyUseType */
    { WC_NID_anyExtendedKeyUsage, EKU_ANY_OID, oidCertKeyUseType,
      "anyExtendedKeyUsage", "Any Extended Key Usage"},
    { EKU_SERVER_AUTH_OID, EKU_SERVER_AUTH_OID, oidCertKeyUseType,
      "serverAuth", "TLS Web Server Authentication"},
    { EKU_CLIENT_AUTH_OID, EKU_CLIENT_AUTH_OID, oidCertKeyUseType,
      "clientAuth", "TLS Web Client Authentication"},
    { EKU_OCSP_SIGN_OID, EKU_OCSP_SIGN_OID, oidCertKeyUseType,
      "OCSPSigning", "OCSP Signing"},

    /* oidCertNameType */
    /* Ordered most commonly used first: entries of a group are searched
     * linearly. Distinguished name attributes are first, then the extended
     * validation ones, then the rarely used and legacy. */
    { WC_NID_commonName, WC_NAME_COMMON_NAME_OID, oidCertNameType,
      "CN", "commonName"},
    { WC_NID_organizationName, WC_NAME_ORGANIZATION_NAME_OID, oidCertNameType,
      "O", "organizationName"},
    { WC_NID_organizationalUnitName, WC_NAME_ORGANIZATION_UNIT_NAME_OID,
      oidCertNameType, "OU", "organizationalUnitName"},
    { WC_NID_countryName, WC_NAME_COUNTRY_NAME_OID, oidCertNameType,
      "C", "countryName"},
    { WC_NID_stateOrProvinceName, WC_NAME_STATE_NAME_OID, oidCertNameType,
      "ST", "stateOrProvinceName"},
    { WC_NID_localityName, WC_NAME_LOCALITY_NAME_OID, oidCertNameType,
      "L", "localityName"},
    { WC_NID_emailAddress, WC_NAME_EMAIL_ADDRESS_OID, oidCertNameType,
      "emailAddress", "emailAddress"},
    { WC_NID_serialNumber, WC_NAME_SERIAL_NUMBER_OID, oidCertNameType,
      "serialNumber", "serialNumber"},
    { WC_NID_domainComponent, WC_NAME_DOMAIN_COMPONENT_OID, oidCertNameType,
      "DC", "domainComponent"},

    /* Extended validation attributes. */
    { WC_NID_streetAddress, WC_NAME_STREET_ADDRESS_OID, oidCertNameType,
      "street", "streetAddress"},
    { WC_NID_postalCode, WC_NAME_POSTAL_CODE_OID, oidCertNameType, "postalCode",
      "postalCode"},
    { WC_NID_businessCategory, WC_NAME_BUSINESS_CATEGORY_OID, oidCertNameType,
      "businessCategory", "businessCategory"},
    { WC_NID_jurisdictionCountryName, WC_NAME_JURIS_COUNTRY_OID,
      oidCertNameType, "jurisdictionC", "jurisdictionCountryName"},
    { WC_NID_jurisdictionStateOrProvinceName, WC_NAME_JURIS_STATE_PROV_OID,
      oidCertNameType, "jurisdictionST", "jurisdictionStateOrProvinceName"},

    /* Rarely used and legacy attributes. */
    { WC_NID_userId, WC_NAME_USER_ID_OID, oidCertNameType, "UID", "userId"},
    { WC_NID_title, WC_NAME_TITLE_OID, oidCertNameType, "title", "title"},
    { WC_NID_description, WC_NAME_DESCRIPTION_OID, oidCertNameType,
      "description", "description"},
    { WC_NID_rfc822Mailbox, WC_NAME_RFC822_MAILBOX_OID, oidCertNameType,
      "rfc822Mailbox", "rfc822Mailbox"},
    { WC_NID_favouriteDrink, WC_NAME_FAVOURITE_DRINK_OID, oidCertNameType,
      "favouriteDrink", "favouriteDrink"},
#if !defined(WOLFSSL_CERT_REQ)
    { WC_NID_surname, WC_NAME_SURNAME_OID, oidCertNameType, "SN", "surname"},
#endif
    { WC_NID_netscape_cert_type, NETSCAPE_CT_OID, oidCertNameType,
      "nsCertType", "Netscape Cert Type"},
#if defined(WOLFSSL_APACHE_HTTPD) && defined(OPENSSL_EXTRA)
    /* "1.3.6.1.5.5.7.8.7" */
    { WC_NID_id_on_dnsSRV, WOLFSSL_DNS_SRV_SUM, oidCertNameType,
      WOLFSSL_SN_DNS_SRV, WOLFSSL_LN_DNS_SRV },
#endif

#if defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_NAME_ALL)
    { WC_NID_pkcs9_challengePassword, CHALLENGE_PASSWORD_OID,
            oidCsrAttrType, "challengePassword", "challengePassword"},
    { WC_NID_pkcs9_contentType, PKCS9_CONTENT_TYPE_OID,
        oidCsrAttrType, "contentType", "contentType" },
    { WC_NID_pkcs9_unstructuredName, UNSTRUCTURED_NAME_OID,
        oidCsrAttrType, "unstructuredName", "unstructuredName" },
    { WC_NID_name, WC_NAME_NAME_OID, oidCsrAttrType, "name", "name" },
    { WC_NID_surname, SURNAME_OID,
        oidCsrAttrType, "surname", "surname" },
    { WC_NID_givenName, WC_NAME_GIVEN_NAME_OID,
        oidCsrAttrType, "givenName", "givenName" },
    { WC_NID_initials, WC_NAME_INITIALIS_OID,
        oidCsrAttrType, "initials", "initials" },
    { WC_NID_dnQualifier, DNQUALIFIER_OID,
        oidCsrAttrType, "dnQualifier", "dnQualifier" },
    { WC_NID_serialNumber, SERIAL_NUMBER_OID,
        oidCsrAttrType, "serialNumber", "serialNumber" },
    { WC_NID_userId, USER_ID_OID, oidCsrAttrType, "UID", "userId" },
#endif
#endif
#ifdef OPENSSL_EXTRA /* OPENSSL_EXTRA_X509_SMALL only needs the above */
        /* oidHashType */
        /* Ordered most commonly used first: entries of a group are searched
         * linearly. SHA-2 first, then SHA-3, then the rarely used. Legacy
         * digests are last. */
    #ifdef WOLFSSL_SM3
        { WC_NID_sm3, SM3h, oidHashType, "SM3", "sm3"},
    #endif
    #ifndef NO_SHA256
        { WC_NID_sha256, SHA256h, oidHashType, "SHA256", "sha256"},
    #endif
    #ifdef WOLFSSL_SHA384
        { WC_NID_sha384, SHA384h, oidHashType, "SHA384", "sha384"},
    #endif
    #ifdef WOLFSSL_SHA512
        { WC_NID_sha512, SHA512h, oidHashType, "SHA512", "sha512"},
    #endif
    #ifdef WOLFSSL_SHA224
        { WC_NID_sha224, SHA224h, oidHashType, "SHA224", "sha224"},
    #endif
    #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_256
        { WC_NID_sha3_256, SHA3_256h, oidHashType, "SHA3-256", "sha3-256"},
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        { WC_NID_sha3_384, SHA3_384h, oidHashType, "SHA3-384", "sha3-384"},
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        { WC_NID_sha3_512, SHA3_512h, oidHashType, "SHA3-512", "sha3-512"},
        #endif
        #ifndef WOLFSSL_NOSHA3_224
        { WC_NID_sha3_224, SHA3_224h, oidHashType, "SHA3-224", "sha3-224"},
        #endif
    #endif /* WOLFSSL_SHA3 */
    #ifdef WOLFSSL_SHAKE128
        { WC_NID_shake128, SHAKE128h, oidHashType, "SHAKE128", "shake128"},
    #endif
    #ifdef WOLFSSL_SHAKE256
        { WC_NID_shake256, SHAKE256h, oidHashType, "SHAKE256", "shake256"},
    #endif

        /* Legacy digests. */
    #ifndef NO_SHA
        { WC_NID_sha1, SHAh, oidHashType, "SHA1", "sha1"},
    #endif
    #ifndef NO_MD5
        { WC_NID_md5, MD5h, oidHashType, "MD5", "md5"},
    #endif
    #ifndef NO_MD4
        { WC_NID_md4, MD4h, oidHashType, "MD4", "md4"},
    #endif
    #ifdef WOLFSSL_MD2
        { WC_NID_md2, MD2h, oidHashType, "MD2", "md2"},
    #endif
        /* oidSigType */
        /* Ordered most commonly used first: entries of a group are searched
         * linearly. Legacy signature algorithms are last. */
    #ifdef HAVE_ED25519
        { WC_NID_ED25519, CTC_ED25519, oidSigType, "ED25519", "ED25519"},
    #endif
    #ifdef HAVE_ED448
        { WC_NID_ED448, CTC_ED448, oidSigType, "ED448", "ED448"},
    #endif
    #ifndef NO_RSA
        #ifndef NO_SHA256
        { WC_NID_sha256WithRSAEncryption, CTC_SHA256wRSA, oidSigType,
          "RSA-SHA256", "sha256WithRSAEncryption"},
        #endif
        #ifdef WOLFSSL_SHA384
        { WC_NID_sha384WithRSAEncryption, CTC_SHA384wRSA, oidSigType,
          "RSA-SHA384", "sha384WithRSAEncryption"},
        #endif
        #ifdef WOLFSSL_SHA512
        { WC_NID_sha512WithRSAEncryption, CTC_SHA512wRSA, oidSigType,
          "RSA-SHA512", "sha512WithRSAEncryption"},
        #endif
        #ifdef WC_RSA_PSS
        { WC_NID_rsassaPss, CTC_RSASSAPSS, oidSigType,
          "RSASSA-PSS", "rsassaPss" },
        #endif
        #ifdef WOLFSSL_SHA224
        { WC_NID_sha224WithRSAEncryption, CTC_SHA224wRSA, oidSigType,
          "RSA-SHA224", "sha224WithRSAEncryption"},
        #endif
        #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_256
        { WC_NID_RSA_SHA3_256, CTC_SHA3_256wRSA, oidSigType, "RSA-SHA3-256",
          "sha3-256WithRSAEncryption"},
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        { WC_NID_RSA_SHA3_384, CTC_SHA3_384wRSA, oidSigType, "RSA-SHA3-384",
          "sha3-384WithRSAEncryption"},
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        { WC_NID_RSA_SHA3_512, CTC_SHA3_512wRSA, oidSigType, "RSA-SHA3-512",
          "sha3-512WithRSAEncryption"},
        #endif
        #ifndef WOLFSSL_NOSHA3_224
        { WC_NID_RSA_SHA3_224, CTC_SHA3_224wRSA, oidSigType, "RSA-SHA3-224",
          "sha3-224WithRSAEncryption"},
        #endif
        #endif
    #endif /* NO_RSA */
    #ifdef HAVE_ECC
        #ifndef NO_SHA256
        { WC_NID_ecdsa_with_SHA256, CTC_SHA256wECDSA, oidSigType,
          "ecdsa-with-SHA256","sha256WithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA384
        { WC_NID_ecdsa_with_SHA384, CTC_SHA384wECDSA, oidSigType,
          "ecdsa-with-SHA384","sha384WithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA512
        { WC_NID_ecdsa_with_SHA512, CTC_SHA512wECDSA, oidSigType,
          "ecdsa-with-SHA512","sha512WithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA224
        { WC_NID_ecdsa_with_SHA224, CTC_SHA224wECDSA, oidSigType,
          "ecdsa-with-SHA224","sha224WithECDSA"},
        #endif
        #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_256
        { WC_NID_ecdsa_with_SHA3_256, CTC_SHA3_256wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-256", "ecdsa_with_SHA3-256"},
        #endif
        #ifndef WOLFSSL_NOSHA3_384
        { WC_NID_ecdsa_with_SHA3_384, CTC_SHA3_384wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-384", "ecdsa_with_SHA3-384"},
        #endif
        #ifndef WOLFSSL_NOSHA3_512
        { WC_NID_ecdsa_with_SHA3_512, CTC_SHA3_512wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-512", "ecdsa_with_SHA3-512"},
        #endif
        #ifndef WOLFSSL_NOSHA3_224
        { WC_NID_ecdsa_with_SHA3_224, CTC_SHA3_224wECDSA, oidSigType,
          "id-ecdsa-with-SHA3-224", "ecdsa_with_SHA3-224"},
        #endif
        #endif
    #endif /* HAVE_ECC */
        /* Legacy MD2, MD5 and SHA-1 based signatures. */
    #ifndef NO_RSA
        #ifdef WOLFSSL_MD2
        { WC_NID_md2WithRSAEncryption, CTC_MD2wRSA, oidSigType, "RSA-MD2",
          "md2WithRSAEncryption"},
        #endif
        #ifndef NO_MD5
        { WC_NID_md5WithRSAEncryption, CTC_MD5wRSA, oidSigType, "RSA-MD5",
          "md5WithRSAEncryption"},
        #endif
        #ifndef NO_SHA
        { WC_NID_sha1WithRSAEncryption, CTC_SHAwRSA, oidSigType, "RSA-SHA1",
          "sha1WithRSAEncryption"},
        #endif
    #endif /* NO_RSA */
    #ifdef HAVE_ECC
        #ifndef NO_SHA
        { WC_NID_ecdsa_with_SHA1, CTC_SHAwECDSA, oidSigType, "ecdsa-with-SHA1",
          "shaWithECDSA"},
        #endif
    #endif /* HAVE_ECC */
        /* DSA is rarely used. */
    #ifndef NO_DSA
        #ifndef NO_SHA
        { WC_NID_dsaWithSHA1, CTC_SHAwDSA, oidSigType,
          "DSA-SHA1", "dsaWithSHA1"},
        { WC_NID_dsa_with_SHA256, CTC_SHA256wDSA, oidSigType, "dsa_with_SHA256",
          "dsa_with_SHA256"},
        #endif
    #endif /* NO_DSA */

        /* oidKeyType */
    #ifndef NO_DSA
        { WC_NID_dsa, DSAk, oidKeyType, "DSA", "dsaEncryption"},
    #endif /* NO_DSA */
    #ifndef NO_RSA
        { WC_NID_rsaEncryption, RSAk, oidKeyType, "rsaEncryption",
          "rsaEncryption"},
    #ifdef WC_RSA_PSS
        { WC_NID_rsassaPss, RSAPSSk, oidKeyType, "RSASSA-PSS", "rsassaPss"},
    #endif
    #endif /* NO_RSA */
    #ifdef HAVE_ECC
        { WC_NID_X9_62_id_ecPublicKey, ECDSAk, oidKeyType, "id-ecPublicKey",
                                                        "id-ecPublicKey"},
    #endif /* HAVE_ECC */
    #ifndef NO_DH
        { WC_NID_dhKeyAgreement, DHk, oidKeyType, "dhKeyAgreement",
          "dhKeyAgreement"},
    #endif
    #ifdef HAVE_ED448
        { WC_NID_ED448, ED448k,  oidKeyType, "ED448", "ED448"},
    #endif
    #ifdef HAVE_ED25519
        { WC_NID_ED25519, ED25519k,  oidKeyType, "ED25519", "ED25519"},
    #endif
    #ifdef HAVE_FALCON
        { CTC_FALCON_LEVEL1, FALCON_LEVEL1k,  oidKeyType, "Falcon Level 1",
                                                          "Falcon Level 1"},
        { CTC_FALCON_LEVEL5, FALCON_LEVEL5k,  oidKeyType, "Falcon Level 5",
                                                          "Falcon Level 5"},
    #endif /* HAVE_FALCON */
    #ifdef WOLFSSL_HAVE_MLDSA
    #ifdef WOLFSSL_MLDSA_FIPS204_DRAFT
        /* Pre-standardization (NIST PQC round 3) Dilithium OID labels.
         * These coexist with the FIPS 204 "ML-DSA 44/65/87" entries below
         * and are intentionally kept under the Dilithium name. */
        { CTC_DILITHIUM_LEVEL2, DILITHIUM_LEVEL2k,  oidKeyType,
          "Dilithium Level 2", "Dilithium Level 2"},
        { CTC_DILITHIUM_LEVEL3, DILITHIUM_LEVEL3k,  oidKeyType,
          "Dilithium Level 3", "Dilithium Level 3"},
        { CTC_DILITHIUM_LEVEL5, DILITHIUM_LEVEL5k,  oidKeyType,
          "Dilithium Level 5", "Dilithium Level 5"},
    #endif /* WOLFSSL_MLDSA_FIPS204_DRAFT */
        { CTC_ML_DSA_44, ML_DSA_44k,  oidKeyType,
          "ML-DSA 44", "ML-DSA 44"},
        { CTC_ML_DSA_65, ML_DSA_65k,  oidKeyType,
          "ML-DSA 65", "ML-DSA 65"},
        { CTC_ML_DSA_87, ML_DSA_87k,  oidKeyType,
          "ML-DSA 87", "ML-DSA 87"},
    #endif /* WOLFSSL_HAVE_MLDSA */

        /* oidCurveType */
    #ifdef HAVE_ECC
        /* Ordered most commonly used first: entries of a group are searched
         * linearly. */
    #ifdef WOLFSSL_SM2
        { WC_NID_sm2, ECC_SM2P256V1_OID, oidCurveType, "sm2", "sm2"},
    #endif
        { WC_NID_X9_62_prime256v1, ECC_SECP256R1_OID, oidCurveType,
          "prime256v1", "prime256v1"},
        { WC_NID_secp224r1, ECC_SECP224R1_OID,  oidCurveType, "secp224r1",
          "secp224r1"},
        { WC_NID_secp384r1, ECC_SECP384R1_OID,  oidCurveType, "secp384r1",
          "secp384r1"},
        { WC_NID_secp521r1, ECC_SECP521R1_OID,  oidCurveType, "secp521r1",
          "secp521r1"},

        { WC_NID_brainpoolP160r1, ECC_BRAINPOOLP160R1_OID,  oidCurveType,
          "brainpoolP160r1", "brainpoolP160r1"},
        { WC_NID_brainpoolP192r1, ECC_BRAINPOOLP192R1_OID,  oidCurveType,
          "brainpoolP192r1", "brainpoolP192r1"},
        { WC_NID_brainpoolP224r1, ECC_BRAINPOOLP224R1_OID,  oidCurveType,
          "brainpoolP224r1", "brainpoolP224r1"},
        { WC_NID_brainpoolP256r1, ECC_BRAINPOOLP256R1_OID,  oidCurveType,
          "brainpoolP256r1", "brainpoolP256r1"},
        { WC_NID_brainpoolP320r1, ECC_BRAINPOOLP320R1_OID,  oidCurveType,
          "brainpoolP320r1", "brainpoolP320r1"},
        { WC_NID_brainpoolP384r1, ECC_BRAINPOOLP384R1_OID,  oidCurveType,
          "brainpoolP384r1", "brainpoolP384r1"},
        { WC_NID_brainpoolP512r1, ECC_BRAINPOOLP512R1_OID,  oidCurveType,
          "brainpoolP512r1", "brainpoolP512r1"},

        { WC_NID_X9_62_prime192v1, ECC_SECP192R1_OID, oidCurveType,
          "prime192v1", "prime192v1"},
        { WC_NID_X9_62_prime192v2, ECC_PRIME192V2_OID, oidCurveType,
          "prime192v2", "prime192v2"},
        { WC_NID_X9_62_prime192v3, ECC_PRIME192V3_OID, oidCurveType,
          "prime192v3", "prime192v3"},

        { WC_NID_X9_62_prime239v1, ECC_PRIME239V1_OID, oidCurveType,
          "prime239v1", "prime239v1"},
        { WC_NID_X9_62_prime239v2, ECC_PRIME239V2_OID, oidCurveType,
          "prime239v2", "prime239v2"},
        { WC_NID_X9_62_prime239v3, ECC_PRIME239V3_OID, oidCurveType,
          "prime239v3", "prime239v3"},

        { WC_NID_secp112r1, ECC_SECP112R1_OID,  oidCurveType, "secp112r1",
          "secp112r1"},
        { WC_NID_secp112r2, ECC_SECP112R2_OID,  oidCurveType, "secp112r2",
          "secp112r2"},

        { WC_NID_secp128r1, ECC_SECP128R1_OID,  oidCurveType, "secp128r1",
          "secp128r1"},
        { WC_NID_secp128r2, ECC_SECP128R2_OID,  oidCurveType, "secp128r2",
          "secp128r2"},

        { WC_NID_secp160r1, ECC_SECP160R1_OID,  oidCurveType, "secp160r1",
          "secp160r1"},
        { WC_NID_secp160r2, ECC_SECP160R2_OID,  oidCurveType, "secp160r2",
          "secp160r2"},

        { WC_NID_secp160k1, ECC_SECP160K1_OID,  oidCurveType, "secp160k1",
          "secp160k1"},
        { WC_NID_secp192k1, ECC_SECP192K1_OID,  oidCurveType, "secp192k1",
          "secp192k1"},
        { WC_NID_secp224k1, ECC_SECP224K1_OID,  oidCurveType, "secp224k1",
          "secp224k1"},
        { WC_NID_secp256k1, ECC_SECP256K1_OID,  oidCurveType, "secp256k1",
          "secp256k1"},
    #endif /* HAVE_ECC */

        /* oidBlkType */
    #ifdef WOLFSSL_AES_128
        { AES128CBCb, AES128CBCb, oidBlkType, "AES-128-CBC", "aes-128-cbc"},
    #endif
    #ifdef WOLFSSL_AES_192
        { AES192CBCb, AES192CBCb, oidBlkType, "AES-192-CBC", "aes-192-cbc"},
    #endif
    #ifdef WOLFSSL_AES_256
        { AES256CBCb, AES256CBCb, oidBlkType, "AES-256-CBC", "aes-256-cbc"},
    #endif
    #ifndef NO_DES3
        { WC_NID_des, DESb, oidBlkType, "DES-CBC", "des-cbc"},
        { WC_NID_des3, DES3b, oidBlkType, "DES-EDE3-CBC", "des-ede3-cbc"},
    #endif /* !NO_DES3 */
    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        { WC_NID_chacha20_poly1305, WC_NID_chacha20_poly1305, oidBlkType,
          "ChaCha20-Poly1305", "chacha20-poly1305"},
    #endif

        /* oidOcspType */
    #ifdef HAVE_OCSP
        { WC_NID_id_pkix_OCSP_basic, OCSP_BASIC_OID, oidOcspType,
          "basicOCSPResponse", "Basic OCSP Response"},
        { OCSP_NONCE_OID, OCSP_NONCE_OID, oidOcspType, "Nonce", "OCSP Nonce"},
    #endif /* HAVE_OCSP */

    #ifndef NO_PWDBASED
        /* oidKdfType */
        { PBKDF2_OID, PBKDF2_OID, oidKdfType, "PBKDFv2", "PBKDF2"},

        /* oidPBEType */
        { PBE_SHA1_RC4_128, PBE_SHA1_RC4_128, oidPBEType,
          "PBE-SHA1-RC4-128", "pbeWithSHA1And128BitRC4"},
        { PBE_SHA1_DES, PBE_SHA1_DES, oidPBEType, "PBE-SHA1-DES",
          "pbeWithSHA1AndDES-CBC"},
        { PBE_SHA1_DES3, PBE_SHA1_DES3, oidPBEType, "PBE-SHA1-3DES",
          "pbeWithSHA1And3-KeyTripleDES-CBC"},
    #endif

        /* oidKeyWrapType */
    #ifdef WOLFSSL_AES_128
        { AES128_WRAP, AES128_WRAP, oidKeyWrapType, "AES-128 wrap",
          "aes128-wrap"},
    #endif
    #ifdef WOLFSSL_AES_192
        { AES192_WRAP, AES192_WRAP, oidKeyWrapType, "AES-192 wrap",
          "aes192-wrap"},
    #endif
    #ifdef WOLFSSL_AES_256
        { AES256_WRAP, AES256_WRAP, oidKeyWrapType, "AES-256 wrap",
          "aes256-wrap"},
    #endif

    #ifndef NO_PKCS7
        #ifndef NO_DH
        /* oidCmsKeyAgreeType */
            #ifndef NO_SHA
        { dhSinglePass_stdDH_sha1kdf_scheme, dhSinglePass_stdDH_sha1kdf_scheme,
          oidCmsKeyAgreeType, "dhSinglePass-stdDH-sha1kdf-scheme",
          "dhSinglePass-stdDH-sha1kdf-scheme"},
            #endif
            #ifdef WOLFSSL_SHA224
        { dhSinglePass_stdDH_sha224kdf_scheme,
          dhSinglePass_stdDH_sha224kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha224kdf-scheme",
          "dhSinglePass-stdDH-sha224kdf-scheme"},
            #endif
            #ifndef NO_SHA256
        { dhSinglePass_stdDH_sha256kdf_scheme,
          dhSinglePass_stdDH_sha256kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha256kdf-scheme",
          "dhSinglePass-stdDH-sha256kdf-scheme"},
            #endif
            #ifdef WOLFSSL_SHA384
        { dhSinglePass_stdDH_sha384kdf_scheme,
          dhSinglePass_stdDH_sha384kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha384kdf-scheme",
          "dhSinglePass-stdDH-sha384kdf-scheme"},
            #endif
            #ifdef WOLFSSL_SHA512
        { dhSinglePass_stdDH_sha512kdf_scheme,
          dhSinglePass_stdDH_sha512kdf_scheme, oidCmsKeyAgreeType,
          "dhSinglePass-stdDH-sha512kdf-scheme",
          "dhSinglePass-stdDH-sha512kdf-scheme"},
            #endif
        #endif
    #endif
    #if defined(WOLFSSL_APACHE_HTTPD)
        /* "1.3.6.1.5.5.7.1.24" */
        { WC_NID_tlsfeature, WOLFSSL_TLS_FEATURE_SUM, oidTlsExtType,
            WOLFSSL_SN_TLS_FEATURE, WOLFSSL_LN_TLS_FEATURE },
    #endif
#endif /* OPENSSL_EXTRA */
};

#define WOLFSSL_OBJECT_INFO_SZ \
                (sizeof(wolfssl_object_info) / sizeof(*wolfssl_object_info))
const size_t wolfssl_object_info_sz = WOLFSSL_OBJECT_INFO_SZ;

/* Index of the runs of entries in wolfssl_object_info[] that share an OID
 * group. Entries of a group are contiguous, so a group is one [start, start +
 * count) range. Looking up by group first bounds a search to that range
 * instead of the whole table.
 *
 * The entries of wolfssl_object_info[] are conditionally compiled, so the
 * ranges differ with build configuration and are calculated in
 * wolfssl_object_info_slice_init() at wolfSSL_Init() time.
 */
typedef struct WolfsslObjectInfoSlice {
    word32 type;
    word16 start;
    word16 count;
} WolfsslObjectInfoSlice;

/* Maximum number of OID groups with entries in wolfssl_object_info[]. */
#define WOLFSSL_OBJECT_INFO_SLICE_MAX   24

static WolfsslObjectInfoSlice wolfssl_object_info_slice[
    WOLFSSL_OBJECT_INFO_SLICE_MAX];
/* Number of slices calculated. 0 when not calculated yet. */
static int wolfssl_object_info_slice_cnt = 0;

/* Calculate the index of OID group runs in wolfssl_object_info[].
 *
 * Entries of a group are contiguous. Called once from wolfSSL_Init().
 * On overflow the index is discarded and lookups search all entries.
 */
void wolfssl_object_info_slice_init(void)
{
    size_t i;
    int cnt = 0;

    for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++) {
        /* Continue the run when the group is the same as the last. */
        if ((cnt > 0) && (wolfssl_object_info[i].type ==
                wolfssl_object_info_slice[cnt - 1].type)) {
            wolfssl_object_info_slice[cnt - 1].count++;
            continue;
        }
        /* More groups than expected - fall back to searching all entries. */
        if (cnt == WOLFSSL_OBJECT_INFO_SLICE_MAX) {
            WOLFSSL_MSG("OID group index too small");
            cnt = 0;
            break;
        }
        wolfssl_object_info_slice[cnt].type  = wolfssl_object_info[i].type;
        wolfssl_object_info_slice[cnt].start = (word16)i;
        wolfssl_object_info_slice[cnt].count = 1;
        cnt++;
    }

    wolfssl_object_info_slice_cnt = cnt;
}

/* Get the range of wolfssl_object_info[] entries in an OID group.
 *
 * When the index has not been calculated, all entries are in range. Callers
 * must check the group of an entry as well.
 *
 * start and end are always set: an empty range when the group has no entries.
 *
 * @param [in]  grp    OID group to find.
 * @param [out] start  First index of group.
 * @param [out] end    One past last index of group.
 * @return  1 when there is a range to search.
 * @return  0 when no entries have this group.
 */
static int wolfssl_object_info_range(word32 grp, size_t* start, size_t* end)
{
    int i;

    /* Empty range so that a caller looping over it does nothing. */
    *start = 0;
    *end   = 0;

    for (i = 0; i < wolfssl_object_info_slice_cnt; i++) {
        if (wolfssl_object_info_slice[i].type == grp) {
            *start = wolfssl_object_info_slice[i].start;
            *end   = *start + wolfssl_object_info_slice[i].count;
            return 1;
        }
    }
    /* Index not calculated - search all entries. */
    if (wolfssl_object_info_slice_cnt == 0) {
        *end = WOLFSSL_OBJECT_INFO_SZ;
        return 1;
    }

    return 0;
}

/* Get the OID sum for a NID in an OID group.
 *
 * @param [in] nid  NID to find.
 * @param [in] grp  OID group the NID is in.
 * @return  OID sum on success.
 * @return  -1 as an unsigned value when the NID is not in the group.
 */
word32 nid2oid(int nid, int grp)
{
    size_t i;
    size_t end;

    /* Find the entry with the NID in the group. Only the entries of the
     * group need to be searched. Match on group as well as NID: the same NID
     * may appear in more than one group. */
    if (wolfssl_object_info_range((word32)grp, &i, &end)) {
        for (; i < end; i++) {
            if ((wolfssl_object_info[i].nid == nid) &&
                    (wolfssl_object_info[i].type == (word32)grp)) {
                return (word32)wolfssl_object_info[i].id;
            }
        }
    }

    WOLFSSL_MSG("NID not in table");
    /* MSVC warns without the cast */
    return (word32)-1;
}

/* Get the NID for an OID sum.
 *
 * The entries of grp are searched first. When not found there, every entry is
 * searched as callers may not know the group.
 *
 * @param [in] oid  OID sum to find.
 * @param [in] grp  OID group the OID is expected to be in.
 * @return  NID on success.
 * @return  WOLFSSL_FATAL_ERROR when the OID is not in the table.
 */
int oid2nid(word32 oid, int grp)
{
    size_t i;
    size_t end;

    /* Find the entry with the OID in the group. Only the entries of the
     * group need to be searched. */
    if (wolfssl_object_info_range((word32)grp, &i, &end)) {
        for (; i < end; i++) {
            if ((wolfssl_object_info[i].id == (int)oid) &&
                    (wolfssl_object_info[i].type == (word32)grp)) {
                return wolfssl_object_info[i].nid;
            }
        }
    }

    /* Not in the group - search every entry.
     *
     * Callers may not know the group. wolfSSL_OBJ_txt2obj() creates an object
     * from a numerical OID string with no group set, and
     * wolfSSL_OBJ_obj2nid() then looks it up with grp of 0. */
    for (i = 0; i < WOLFSSL_OBJECT_INFO_SZ; i++) {
        if (wolfssl_object_info[i].id == (int)oid) {
            return wolfssl_object_info[i].nid;
        }
    }

    WOLFSSL_MSG("OID not in table");
    return WOLFSSL_FATAL_ERROR;
}

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(WOLFCRYPT_ONLY)

/* Convert shortname to NID.
 *
 * For OpenSSL compatibility.
 *
 * @param [in] sn  Short name of OID.
 * @return  NID corresponding to shortname on success.
 * @return  WC_NID_undef when not recognized.
 */
int wc_OBJ_sn2nid(const char *sn)
{
    const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
    size_t i;
    WOLFSSL_ENTER("wc_OBJ_sn2nid");
    for (i = 0; i < wolfssl_object_info_sz; i++, obj_info++) {
        if (XSTRCMP(sn, obj_info->sName) == 0)
            return obj_info->nid;
    }
    WOLFSSL_MSG("short name not found in table");
    return WC_NID_undef;
}

    /* NID variables are dependent on compatibility header files currently
     *
     * returns a pointer to a new WOLFSSL_ASN1_OBJECT struct on success and NULL
     *         on fail
     */

    WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj(int id)
    {
        return wolfSSL_OBJ_nid2obj_ex(id, NULL);
    }

    /* Create or fill an ASN.1 OBJECT_ID object from a NID.
     *
     * The OID group is not known and so is looked up in the table with the
     * NID. The DER encoding of the OID is created on the object.
     *
     * @param [in]      id       NID of object.
     * @param [in, out] arg_obj  Object to fill. NULL to allocate a new object.
     * @return  ASN.1 OBJECT_ID object on success.
     * @return  NULL when the NID is not in the table, the short name is too
     *          long or dynamic memory allocation fails.
     */
    WOLFSSL_LOCAL WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj_ex(int id,
                                                WOLFSSL_ASN1_OBJECT* arg_obj)
    {
        word32 oidSz = 0;
        int nid = 0;
        const byte* oid;
        word32 type = 0;
        WOLFSSL_ASN1_OBJECT* obj = arg_obj;
        byte objBuf[MAX_OID_SZ + MAX_LENGTH_SZ + 1]; /* +1 for object tag */
        word32 objSz = 0;
        const char* sName = NULL;
        int i;

#ifdef WOLFSSL_DEBUG_OPENSSL
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2obj");
#endif

        for (i = 0; i < (int)wolfssl_object_info_sz; i++) {
            if (wolfssl_object_info[i].nid == id) {
                nid = id;
                id = wolfssl_object_info[i].id;
                sName = wolfssl_object_info[i].sName;
                type = wolfssl_object_info[i].type;
                break;
            }
        }
        if (i == (int)wolfssl_object_info_sz) {
            WOLFSSL_MSG("NID not in table");
        #ifdef WOLFSSL_QT
            sName = NULL;
            type = (word32)id;
        #else
            return NULL;
        #endif
        }

    #ifdef HAVE_ECC
         if (type == 0 && wc_ecc_get_oid((word32)id, &oid, &oidSz) > 0) {
             type = oidCurveType;
         }
    #endif /* HAVE_ECC */

        if (sName != NULL) {
            if (XSTRLEN(sName) > WOLFSSL_MAX_SNAME - 1) {
                WOLFSSL_MSG("Attempted short name is too large");
                return NULL;
            }
        }

        oid = OidFromId((word32)id, type, &oidSz);

        /* set object ID to buffer */
        if (obj == NULL){
            obj = wolfSSL_ASN1_OBJECT_new();
            if (obj == NULL) {
                WOLFSSL_MSG("Issue creating WOLFSSL_ASN1_OBJECT struct");
                return NULL;
            }
        }
        obj->nid     = nid;
        obj->type    = id;
        obj->grp     = (int)type;

        obj->sName[0] = '\0';
        if (sName != NULL) {
            XMEMCPY(obj->sName, (char*)sName, XSTRLEN((char*)sName));
        }

        objBuf[0] = ASN_OBJECT_ID; objSz++;
        objSz += SetLength(oidSz, objBuf + 1);
        if (oidSz) {
            XMEMCPY(objBuf + objSz, oid, oidSz);
            objSz     += oidSz;
        }

        if (obj->objSz == 0 || objSz != obj->objSz) {
            obj->objSz = objSz;
            if(((obj->dynamic & WOLFSSL_ASN1_DYNAMIC_DATA) != 0) ||
                                                           (obj->obj == NULL)) {
                if (obj->obj != NULL)
                    XFREE((byte*)obj->obj, NULL, DYNAMIC_TYPE_ASN1);
                obj->obj = (byte*)XMALLOC(obj->objSz, NULL, DYNAMIC_TYPE_ASN1);
                if (obj->obj == NULL) {
                    wolfSSL_ASN1_OBJECT_free(obj);
                    return NULL;
                }
                obj->dynamic |= WOLFSSL_ASN1_DYNAMIC_DATA;
            }
            else {
                obj->dynamic &= (unsigned char)~WOLFSSL_ASN1_DYNAMIC_DATA;
            }
        }
        XMEMCPY((byte*)obj->obj, objBuf, obj->objSz);

        (void)type;

        return obj;
    }

    /* Get the description of a numerical OID string.
     *
     * Only OIDs that have no long name in the table are translated.
     *
     * @param [in] oid  Numerical OID string. eg. "2.5.29.37.0".
     * @return  Description of OID on success.
     * @return  NULL when the OID has no description.
     */
    static const char* oid_translate_num_to_str(const char* oid)
    {
        const struct oid_dict {
            const char* num;
            const char* desc;
        } oid_dict[] = {
            { "2.5.29.37.0",       "Any Extended Key Usage" },
            { "1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication" },
            { "1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication" },
            { "1.3.6.1.5.5.7.3.3", "Code Signing" },
            { "1.3.6.1.5.5.7.3.4", "E-mail Protection" },
            { "1.3.6.1.5.5.7.3.8", "Time Stamping" },
            { "1.3.6.1.5.5.7.3.9", "OCSP Signing" },
            { NULL, NULL }
        };
        const struct oid_dict* idx;

        for (idx = oid_dict; idx->num != NULL; idx++) {
            if (!XSTRCMP(oid, idx->num)) {
                return idx->desc;
            }
        }
        return NULL;
    }

    /* Write the numerical form of an ASN.1 OBJECT_ID object's OID into a
     * buffer.
     *
     * String is of the form "1.2.840.113549.1.9.1" and is always NUL
     * terminated. Truncated when the buffer is too small.
     *
     * @param [out] buf     Buffer to hold string.
     * @param [in]  bufLen  Length of buffer in bytes.
     * @param [in]  a       ASN.1 OBJECT_ID object.
     * @return  Length of string that would be written, excluding the NUL
     *          terminator, on success.
     * @return  0 when decoding the object fails.
     */
    static int wolfssl_obj2txt_numeric(char *buf, int bufLen,
                                       const WOLFSSL_ASN1_OBJECT *a)
    {
        int bufSz;
        int    length;
        word32 idx = 0;
        byte   tag;

        if (GetASNTag(a->obj, &idx, &tag, a->objSz) != 0) {
            return WOLFSSL_FAILURE;
        }

        if (tag != ASN_OBJECT_ID) {
            WOLFSSL_MSG("Bad ASN1 Object");
            return WOLFSSL_FAILURE;
        }

        if (GetLength((const byte*)a->obj, &idx, &length,
                       a->objSz) < 0 || length < 0) {
            return ASN_PARSE_E;
        }

        if (bufLen < MAX_OID_STRING_SZ) {
            bufSz = bufLen - 1;
        }
        else {
            bufSz = MAX_OID_STRING_SZ;
        }

        if ((bufSz = DecodePolicyOID(buf, (word32)bufSz, a->obj + idx,
                    (word32)length)) <= 0) {
            WOLFSSL_MSG("Error decoding OID");
            return WOLFSSL_FAILURE;
        }

        buf[bufSz] = '\0';

        return bufSz;
    }

    /* If no_name is one then use numerical form, otherwise short name.
     *
     * Returns the buffer size on success, WOLFSSL_FAILURE on error
     */
    int wolfSSL_OBJ_obj2txt(char *buf, int bufLen, const WOLFSSL_ASN1_OBJECT *a,
                            int no_name)
    {
        int bufSz;
        const char* desc;
        const char* name;

        WOLFSSL_ENTER("wolfSSL_OBJ_obj2txt");

        if (buf == NULL || bufLen <= 1 || a == NULL) {
            WOLFSSL_MSG("Bad input argument");
            return WOLFSSL_FAILURE;
        }

        if (no_name == 1) {
            return wolfssl_obj2txt_numeric(buf, bufLen, a);
        }

        /* return long name unless using x509small, then return short name */
#if defined(OPENSSL_EXTRA_X509_SMALL) && !defined(OPENSSL_EXTRA)
        name = a->sName;
#else
        name = wolfSSL_OBJ_nid2ln(wolfSSL_OBJ_obj2nid(a));
#endif

        if (name == NULL) {
            WOLFSSL_MSG("Name not found");
            bufSz = 0;
        }
        else if (XSTRLEN(name) + 1 < (word32)bufLen - 1) {
            bufSz = (int)XSTRLEN(name);
        }
        else {
            bufSz = bufLen - 1;
        }
        if (bufSz) {
            XMEMCPY(buf, name, (size_t)bufSz);
        }
        else if (a->type == WOLFSSL_GEN_DNS || a->type == WOLFSSL_GEN_EMAIL ||
                 a->type == WOLFSSL_GEN_URI) {
            size_t objLen = XSTRLEN((const char*)a->obj);
            if (objLen >= (size_t)bufLen) {
                bufSz = bufLen - 1;
            }
            else {
                bufSz = (int)objLen;
            }
            XMEMCPY(buf, a->obj, (size_t)bufSz);
        }
        else if ((bufSz = wolfssl_obj2txt_numeric(buf, bufLen, a)) > 0) {
            if ((desc = oid_translate_num_to_str(buf))) {
                bufSz = (int)XSTRLEN(desc);
                bufSz = (int)min((word32)bufSz,(word32) bufLen - 1);
                XMEMCPY(buf, desc, (size_t)bufSz);
            }
        }
        else {
            bufSz = 0;
        }

        buf[bufSz] = '\0';

        return bufSz;
    }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_WPAS_SMALL)
    /* Returns the long name that corresponds with an ASN1_OBJECT nid value.
     *  n : NID value of ASN1_OBJECT to search */
    const char* wolfSSL_OBJ_nid2ln(int n)
    {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t i;
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2ln");
        for (i = 0; i < wolfssl_object_info_sz; i++, obj_info++) {
            if (obj_info->nid == n) {
                return obj_info->lName;
            }
        }
        WOLFSSL_MSG("NID not found in table");
        return NULL;
    }
#endif /* OPENSSL_EXTRA, HAVE_LIGHTY, WOLFSSL_MYSQL_COMPATIBLE, HAVE_STUNNEL,
          WOLFSSL_NGINX, HAVE_POCO_LIB, WOLFSSL_HAPROXY, WOLFSSL_WPAS_SMALL */

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)
    /* Return the corresponding short name for the nid <n>.
     * or NULL if short name can't be found.
     */
    const char * wolfSSL_OBJ_nid2sn(int n) {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t i;
        WOLFSSL_ENTER("wolfSSL_OBJ_nid2sn");

        if (n == WC_NID_md5) {
            /* WC_NID_surname == WC_NID_md5 and WC_NID_surname comes before
             * WC_NID_md5 in wolfssl_object_info. As a result, the loop below
             * will incorrectly return "SN" instead of "MD5." WC_NID_surname
             * isn't the true OpenSSL NID, but other functions rely on this
             * table and modifying it to conform with OpenSSL's NIDs isn't
             * trivial. */
             return "MD5";
        }
        for (i = 0; i < wolfssl_object_info_sz; i++, obj_info++) {
            if (obj_info->nid == n) {
                return obj_info->sName;
            }
        }
        WOLFSSL_MSG_EX("SN not found (nid:%d)",n);
        return NULL;
    }

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    /* Get the NID for a short name.
     *
     * @param [in] sn  Short name of object. eg. "CN".
     * @return  NID on success.
     * @return  WC_NID_undef when sn is NULL or not recognized.
     */
    int wolfSSL_OBJ_sn2nid(const char *sn) {
        WOLFSSL_ENTER("wolfSSL_OBJ_sn2nid");
        if (sn == NULL)
            return WC_NID_undef;
        return wc_OBJ_sn2nid(sn);
    }
#endif

    /* Get the length of the OID in an ASN.1 OBJECT_ID object.
     *
     * @param [in] o  ASN.1 OBJECT_ID object.
     * @return  Length of the OID in bytes on success.
     * @return  0 when o is NULL or decoding the object fails.
     */
    size_t wolfSSL_OBJ_length(const WOLFSSL_ASN1_OBJECT* o)
    {
        size_t ret = 0;
        int err = 0;
        word32 idx = 0;
        int len = 0;

        WOLFSSL_ENTER("wolfSSL_OBJ_length");

        if (o == NULL || o->obj == NULL) {
            WOLFSSL_MSG("Bad argument.");
            err = 1;
        }

        if (err == 0 && GetASNObjectId(o->obj, &idx, &len, o->objSz)) {
            WOLFSSL_MSG("Error parsing ASN.1 header.");
            err = 1;
        }
        if (err == 0) {
            ret = (size_t)len;
        }

        WOLFSSL_LEAVE("wolfSSL_OBJ_length", (int)ret);

        return ret;
    }

    /* Get the OID in an ASN.1 OBJECT_ID object.
     *
     * Returned data is owned by the object and must not be freed.
     *
     * @param [in] o  ASN.1 OBJECT_ID object.
     * @return  OID of object on success.
     * @return  NULL when o is NULL or decoding the object fails.
     */
    const unsigned char* wolfSSL_OBJ_get0_data(const WOLFSSL_ASN1_OBJECT* o)
    {
        const unsigned char* ret = NULL;
        int err = 0;
        word32 idx = 0;
        int len = 0;

        WOLFSSL_ENTER("wolfSSL_OBJ_get0_data");

        if (o == NULL || o->obj == NULL) {
            WOLFSSL_MSG("Bad argument.");
            err = 1;
        }

        if (err == 0 && GetASNObjectId(o->obj, &idx, &len, o->objSz)) {
            WOLFSSL_MSG("Error parsing ASN.1 header.");
            err = 1;
        }
        if (err == 0) {
            ret = o->obj + idx;
        }

        return ret;
    }

    /* Gets the NID value that corresponds with the ASN1 object.
     *
     * o ASN1 object to get NID of
     *
     * Return NID on success and a negative value on failure
     */
    int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o)
    {
        word32 oid = 0;
        word32 idx = 0;
        int ret;

#ifdef WOLFSSL_DEBUG_OPENSSL
        WOLFSSL_ENTER("wolfSSL_OBJ_obj2nid");
#endif

        if (o == NULL) {
            return WOLFSSL_FATAL_ERROR;
        }

        #ifdef WOLFSSL_QT
        if (o->grp == oidCertExtType) {
            /* If nid is an unknown extension, return WC_NID_undef */
            if (wolfSSL_OBJ_nid2sn(o->nid) == NULL)
                return WC_NID_undef;
        }
        #endif

        if (o->nid > 0)
            return o->nid;
        if ((ret = GetObjectId(o->obj, &idx, &oid,
                                    (word32)o->grp, o->objSz)) < 0) {
            if (ret == WC_NO_ERR_TRACE(ASN_OBJECT_ID_E)) {
                /* Put ASN object tag in front and try again */
                int len = SetObjectId((int)o->objSz, NULL) + (int)o->objSz;
                byte* buf = (byte*)XMALLOC((size_t)len, NULL,
                                            DYNAMIC_TYPE_TMP_BUFFER);
                if (!buf) {
                    WOLFSSL_MSG("malloc error");
                    return WOLFSSL_FATAL_ERROR;
                }
                idx = (word32)SetObjectId((int)o->objSz, buf);
                XMEMCPY(buf + idx, o->obj, o->objSz);
                idx = 0;
                ret = GetObjectId(buf, &idx, &oid, (word32)o->grp, (word32)len);
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (ret < 0) {
                    WOLFSSL_MSG("Issue getting OID of object");
                    return WOLFSSL_FATAL_ERROR;
                }
            }
            else {
                WOLFSSL_MSG("Issue getting OID of object");
                return WOLFSSL_FATAL_ERROR;
            }
        }

        return oid2nid(oid, o->grp);
    }

    /* Return the corresponding NID for the long name <ln>
     * or WC_NID_undef if NID can't be found.
     */
    int wolfSSL_OBJ_ln2nid(const char *ln)
    {
        const WOLFSSL_ObjectInfo *obj_info = wolfssl_object_info;
        size_t lnlen;
        WOLFSSL_ENTER("wolfSSL_OBJ_ln2nid");
        if (ln && (lnlen = XSTRLEN(ln)) > 0) {
            /* Accept input like "/commonName=" */
            if (ln[0] == '/') {
                ln++;
                lnlen--;
            }
            if (lnlen) {
                size_t i;

                if (ln[lnlen-1] == '=') {
                    lnlen--;
                }
                for (i = 0; i < wolfssl_object_info_sz; i++, obj_info++) {
                    if (lnlen == XSTRLEN(obj_info->lName) &&
                            XSTRNCMP(ln, obj_info->lName, lnlen) == 0) {
                        return obj_info->nid;
                    }
                }
            }
        }
        return WC_NID_undef;
    }

    /* compares two objects, return 0 if equal */
    int wolfSSL_OBJ_cmp(const WOLFSSL_ASN1_OBJECT* a,
                        const WOLFSSL_ASN1_OBJECT* b)
    {
        WOLFSSL_ENTER("wolfSSL_OBJ_cmp");

        if (a && b && a->obj && b->obj) {
            if (a->objSz == b->objSz) {
                return XMEMCMP(a->obj, b->obj, a->objSz);
            }
            else if (a->type == EXT_KEY_USAGE_OID ||
                     b->type == EXT_KEY_USAGE_OID) {
                /* Special case for EXT_KEY_USAGE_OID so that
                 * cmp will be treated as a substring search */
                /* Used in libest to check for id-kp-cmcRA in
                 * EXT_KEY_USAGE extension */
                unsigned int idx;
                const byte* s; /* shorter */
                unsigned int sLen;
                const byte* l; /* longer */
                unsigned int lLen;
                if (a->objSz > b->objSz) {
                    s = b->obj; sLen = b->objSz;
                    l = a->obj; lLen = a->objSz;
                }
                else {
                    s = a->obj; sLen = a->objSz;
                    l = b->obj; lLen = b->objSz;
                }
                for (idx = 0; idx <= lLen - sLen; idx++) {
                    if (XMEMCMP(l + idx, s, sLen) == 0) {
                        /* Found substring */
                        return 0;
                    }
                }
            }
        }

        return WOLFSSL_FATAL_ERROR;
    }
#endif /* OPENSSL_EXTRA, HAVE_LIGHTY, WOLFSSL_MYSQL_COMPATIBLE, HAVE_STUNNEL,
          WOLFSSL_NGINX, HAVE_POCO_LIB, WOLFSSL_HAPROXY */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_MYSQL_COMPATIBLE) || \
    defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_POCO_LIB) || defined(WOLFSSL_HAPROXY)
    /* Gets the NID value that is related to the OID string passed in. Example
     * string would be "2.5.29.14" for subject key ID.
     *
     * returns NID value on success and WC_NID_undef on error
     */
    int wolfSSL_OBJ_txt2nid(const char* s)
    {
        unsigned int i;
    #ifdef WOLFSSL_CERT_EXT
        int ret;
        unsigned int sum = 0;
        unsigned int outSz = MAX_OID_SZ;
        unsigned char out[MAX_OID_SZ];

        XMEMSET(out, 0, sizeof(out));
    #endif

        WOLFSSL_ENTER("wolfSSL_OBJ_txt2nid");

        if (s == NULL) {
            return WC_NID_undef;
        }

    #ifdef WOLFSSL_CERT_EXT
        ret = EncodePolicyOID(out, &outSz, s, NULL);
        if (ret == 0) {
            /* sum OID */
            sum = wc_oid_sum(out, outSz);
        }
    #endif /* WOLFSSL_CERT_EXT */

        /* get the group that the OID's sum is in
         * @TODO possible conflict with multiples */
        for (i = 0; i < wolfssl_object_info_sz; i++) {
            int len;
        #ifdef WOLFSSL_CERT_EXT
            if (ret == 0) {
                if (wolfssl_object_info[i].id == (int)sum) {
                    return wolfssl_object_info[i].nid;
                }
            }
        #endif

            /* try as a short name */
            len = (int)XSTRLEN(s);
            if ((int)XSTRLEN(wolfssl_object_info[i].sName) == len &&
                XSTRNCMP(wolfssl_object_info[i].sName, s, (word32)len) == 0) {
                return wolfssl_object_info[i].nid;
            }

            /* try as a long name */
            if ((int)XSTRLEN(wolfssl_object_info[i].lName) == len &&
                XSTRNCMP(wolfssl_object_info[i].lName, s, (word32)len) == 0) {
                return wolfssl_object_info[i].nid;
            }
        }

        return WC_NID_undef;
    }
#endif
#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)

    /* Create a new ASN.1 OBJECT_ID object from a name or numerical OID.
     *
     * @param [in] s        Short name, long name or numerical OID string.
     * @param [in] no_name  When 0, s may be a short name, long name or
     *                      numerical OID. When 1, s must be a numerical OID.
     * @return  ASN.1 OBJECT_ID object on success.
     * @return  NULL when s is NULL, not recognized or dynamic memory
     *          allocation fails.
     */
#if defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_CERT_GEN)
    WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name)
    {
        int i, ret;
        int nid = WC_NID_undef;
        unsigned int outSz = MAX_OID_SZ;
        unsigned char out[MAX_OID_SZ];
        WOLFSSL_ASN1_OBJECT* obj;

        WOLFSSL_ENTER("wolfSSL_OBJ_txt2obj");

        if (s == NULL)
            return NULL;

        /* If s is numerical value, try to sum oid */
        ret = EncodePolicyOID(out, &outSz, s, NULL);
        if (ret == 0 && outSz > 0) {
            /* If numerical encode succeeded then just
             * create object from that because sums are
             * not unique and can cause confusion. */
            obj = wolfSSL_ASN1_OBJECT_new();
            if (obj == NULL) {
                WOLFSSL_MSG("Issue creating WOLFSSL_ASN1_OBJECT struct");
                return NULL;
            }
            obj->dynamic |= WOLFSSL_ASN1_DYNAMIC;
            obj->obj = (byte*)XMALLOC(1 + MAX_LENGTH_SZ + outSz, NULL,
                    DYNAMIC_TYPE_ASN1);
            if (obj->obj == NULL) {
                wolfSSL_ASN1_OBJECT_free(obj);
                return NULL;
            }
            obj->dynamic |= WOLFSSL_ASN1_DYNAMIC_DATA;
            i = SetObjectId((int)outSz, (byte*)obj->obj);
            XMEMCPY((byte*)obj->obj + i, out, outSz);
            obj->objSz = (word32)i + outSz;
            return obj;
        }

        /* TODO: update short names in wolfssl_object_info and check OID sums
           are correct */
        for (i = 0; i < (int)wolfssl_object_info_sz; i++) {
            /* Short name, long name, and numerical value are interpreted */
            if (no_name == 0 &&
                ((XSTRCMP(s, wolfssl_object_info[i].sName) == 0) ||
                 (XSTRCMP(s, wolfssl_object_info[i].lName) == 0)))
            {
                    nid = wolfssl_object_info[i].nid;
            }
        }

        if (nid != WC_NID_undef)
            return wolfSSL_OBJ_nid2obj(nid);

        return NULL;
    }
#endif

    /* compatibility function. Its intended use is to remove OID's from an
     * internal table that have been added with OBJ_create. wolfSSL manages its
     * own internal OID values and does not currently support OBJ_create. */
    void wolfSSL_OBJ_cleanup(void)
    {
        WOLFSSL_ENTER("wolfSSL_OBJ_cleanup");
    }

    #ifndef NO_WOLFSSL_STUB
    /* Add an OID to the internal table.
     *
     * Not implemented. wolfSSL manages its own OID values.
     *
     * @param [in] oid  Numerical OID string. Not used.
     * @param [in] sn   Short name of object. Not used.
     * @param [in] ln   Long name of object. Not used.
     * @return  WOLFSSL_FAILURE always.
     */
    int wolfSSL_OBJ_create(const char *oid, const char *sn, const char *ln)
    {
        (void)oid;
        (void)sn;
        (void)ln;
        WOLFSSL_STUB("wolfSSL_OBJ_create");
        return WOLFSSL_FAILURE;
    }
    #endif
#endif /* OPENSSL_ALL || HAVE_LIGHTY || WOLFSSL_MYSQL_COMPATIBLE ||
    HAVE_STUNNEL || WOLFSSL_NGINX || HAVE_POCO_LIB || WOLFSSL_HAPROXY */

#endif /* !WOLFSSL_SSL_ASN1_INCLUDED */
