/* asn1.h
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

/* asn1.h for openssl */

#ifndef WOLFSSL_ASN1_H_
#define WOLFSSL_ASN1_H_

#include <wolfssl/openssl/ssl.h>

#ifndef OPENSSL_COEXIST

#define ASN1_STRING_new       wolfSSL_ASN1_STRING_new
#define ASN1_STRING_type_new  wolfSSL_ASN1_STRING_type_new
#define ASN1_STRING_type      wolfSSL_ASN1_STRING_type
#define ASN1_STRING_set       wolfSSL_ASN1_STRING_set
#define ASN1_OCTET_STRING_set wolfSSL_ASN1_STRING_set
#define ASN1_STRING_free      wolfSSL_ASN1_STRING_free

#define ASN1_get_object       wolfSSL_ASN1_get_object
#define d2i_ASN1_OBJECT       wolfSSL_d2i_ASN1_OBJECT
#define c2i_ASN1_OBJECT       wolfSSL_c2i_ASN1_OBJECT

#define V_ASN1_INTEGER                  WOLFSSL_V_ASN1_INTEGER
#define V_ASN1_NEG                      WOLFSSL_V_ASN1_NEG
#define V_ASN1_NEG_INTEGER              WOLFSSL_V_ASN1_NEG_INTEGER
#define V_ASN1_NEG_ENUMERATED           WOLFSSL_V_ASN1_NEG_ENUMERATED

/* Type for ASN1_print_ex */
#define ASN1_STRFLGS_ESC_2253           WOLFSSL_ASN1_STRFLGS_ESC_2253
#define ASN1_STRFLGS_ESC_CTRL           WOLFSSL_ASN1_STRFLGS_ESC_CTRL
#define ASN1_STRFLGS_ESC_MSB            WOLFSSL_ASN1_STRFLGS_ESC_MSB
#define ASN1_STRFLGS_ESC_QUOTE          WOLFSSL_ASN1_STRFLGS_ESC_QUOTE
#define ASN1_STRFLGS_UTF8_CONVERT       WOLFSSL_ASN1_STRFLGS_UTF8_CONVERT
#define ASN1_STRFLGS_IGNORE_TYPE        WOLFSSL_ASN1_STRFLGS_IGNORE_TYPE
#define ASN1_STRFLGS_SHOW_TYPE          WOLFSSL_ASN1_STRFLGS_SHOW_TYPE
#define ASN1_STRFLGS_DUMP_ALL           WOLFSSL_ASN1_STRFLGS_DUMP_ALL
#define ASN1_STRFLGS_DUMP_UNKNOWN       WOLFSSL_ASN1_STRFLGS_DUMP_UNKNOWN
#define ASN1_STRFLGS_DUMP_DER           WOLFSSL_ASN1_STRFLGS_DUMP_DER
#define ASN1_STRFLGS_RFC2253            WOLFSSL_ASN1_STRFLGS_RFC2253

#define MBSTRING_UTF8                   WOLFSSL_MBSTRING_UTF8
#define MBSTRING_ASC                    WOLFSSL_MBSTRING_ASC
#define MBSTRING_BMP                    WOLFSSL_MBSTRING_BMP
#define MBSTRING_UNIV                   WOLFSSL_MBSTRING_UNIV

#define ASN1_UTCTIME_print              wolfSSL_ASN1_UTCTIME_print
#define ASN1_TIME_check                 wolfSSL_ASN1_TIME_check
#define ASN1_TIME_diff                  wolfSSL_ASN1_TIME_diff
#define ASN1_TIME_compare               wolfSSL_ASN1_TIME_compare
#define ASN1_TIME_set                   wolfSSL_ASN1_TIME_set

#define V_ASN1_EOC                      WOLFSSL_V_ASN1_EOC
#define V_ASN1_BOOLEAN                  WOLFSSL_V_ASN1_BOOLEAN
#define V_ASN1_OCTET_STRING             WOLFSSL_V_ASN1_OCTET_STRING
#define V_ASN1_NULL                     WOLFSSL_V_ASN1_NULL
#define V_ASN1_OBJECT                   WOLFSSL_V_ASN1_OBJECT
#define V_ASN1_UTF8STRING               WOLFSSL_V_ASN1_UTF8STRING
#define V_ASN1_SEQUENCE                 WOLFSSL_V_ASN1_SEQUENCE
#define V_ASN1_SET                      WOLFSSL_V_ASN1_SET
#define V_ASN1_PRINTABLESTRING          WOLFSSL_V_ASN1_PRINTABLESTRING
#define V_ASN1_T61STRING                WOLFSSL_V_ASN1_T61STRING
#define V_ASN1_IA5STRING                WOLFSSL_V_ASN1_IA5STRING
#define V_ASN1_UTCTIME                  WOLFSSL_V_ASN1_UTCTIME
#define V_ASN1_GENERALIZEDTIME          WOLFSSL_V_ASN1_GENERALIZEDTIME
#define V_ASN1_UNIVERSALSTRING          WOLFSSL_V_ASN1_UNIVERSALSTRING
#define V_ASN1_BMPSTRING                WOLFSSL_V_ASN1_BMPSTRING

#define V_ASN1_CONSTRUCTED              WOLFSSL_V_ASN1_CONSTRUCTED

#define ASN1_STRING_FLAG_BITS_LEFT      WOLFSSL_ASN1_STRING_FLAG_BITS_LEFT
#define ASN1_STRING_FLAG_NDEF           WOLFSSL_ASN1_STRING_FLAG_NDEF
#define ASN1_STRING_FLAG_CONT           WOLFSSL_ASN1_STRING_FLAG_CONT
#define ASN1_STRING_FLAG_MSTRING        WOLFSSL_ASN1_STRING_FLAG_MSTRING
#define ASN1_STRING_FLAG_EMBED          WOLFSSL_ASN1_STRING_FLAG_EMBED

/* X.509 PKI size limits from RFC2459 (appendix A) */
/* internally our limit is CTC_NAME_SIZE (64) - overridden with WC_CTC_NAME_SIZE */
#define ub_name                         WOLFSSL_ub_name
#define ub_common_name                  WOLFSSL_ub_common_name
#define ub_locality_name                WOLFSSL_ub_locality_name
#define ub_state_name                   WOLFSSL_ub_state_name
#define ub_organization_name            WOLFSSL_ub_organization_name
#define ub_organization_unit_name       WOLFSSL_ub_organization_unit_name
#define ub_title                        WOLFSSL_ub_title
#define ub_email_address                WOLFSSL_ub_email_address

#endif /* !OPENSSL_COEXIST */

WOLFSSL_API WOLFSSL_ASN1_INTEGER *wolfSSL_BN_to_ASN1_INTEGER(
    const WOLFSSL_BIGNUM *bn, WOLFSSL_ASN1_INTEGER *ai);

WOLFSSL_API void wolfSSL_ASN1_TYPE_set(WOLFSSL_ASN1_TYPE *a, int type, void *value);
WOLFSSL_API int wolfSSL_ASN1_TYPE_get(const WOLFSSL_ASN1_TYPE *a);

WOLFSSL_API int wolfSSL_ASN1_get_object(const unsigned char **in, long *len, int *tag,
                                        int *cls, long inLen);

WOLFSSL_API WOLFSSL_ASN1_OBJECT *wolfSSL_c2i_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT **a,
        const unsigned char **pp, long len);

#ifdef OPENSSL_ALL
/* IMPLEMENT_ASN1_FUNCTIONS is strictly for external use only. Internally
 * we don't use this. Some projects use OpenSSL to implement ASN1 types and
 * this section is only to provide those projects with ASN1 functionality. */

typedef void* (*WolfsslAsn1NewCb)(void);
typedef void (*WolfsslAsn1FreeCb)(void*);
typedef int (*WolfsslAsn1i2dCb)(const void*, unsigned char**);
typedef void* (*WolfsslAsn1d2iCb)(void**, const byte **, long);

struct WOLFSSL_ASN1_TEMPLATE {
    /* Type functions */
    WolfsslAsn1NewCb new_func;
    WolfsslAsn1FreeCb free_func;
    WolfsslAsn1i2dCb i2d_func;
    WolfsslAsn1d2iCb d2i_func;
    /* Member info */
    size_t offset;              /* Offset of this field in structure */
    /* DER info */
    int tag;
    byte first_byte;            /* First expected byte. Required for
                                 * IMPLICIT types. */
    byte ex:1;                  /* explicit, name conflicts with C++ keyword */
    byte sequence:1;
};

enum WOLFSSL_ASN1_TYPES {
    WOLFSSL_ASN1_SEQUENCE = 0,
    WOLFSSL_ASN1_CHOICE,
    WOLFSSL_ASN1_OBJECT_TYPE,
};

struct WOLFSSL_ASN1_ITEM {
    enum WOLFSSL_ASN1_TYPES type;
    const struct WOLFSSL_ASN1_TEMPLATE* members; /* If SEQUENCE or CHOICE this
                                                  * contains the contents */
    size_t mcount;                          /* Number of members if SEQUENCE
                                             * or CHOICE */
    size_t size;                            /* Structure size */
    size_t toffset;                         /* Type offset */
};

typedef struct WOLFSSL_ASN1_TEMPLATE WOLFSSL_ASN1_TEMPLATE;
typedef struct WOLFSSL_ASN1_ITEM WOLFSSL_ASN1_ITEM;

#define ASN1_BIT_STRING_FIRST_BYTE ASN_BIT_STRING
#define ASN1_TFLG_EXPLICIT      (0x1 << 0)
#define ASN1_TFLG_SEQUENCE_OF   (0x1 << 1)
#define ASN1_TFLG_IMPTAG        (0x1 << 2)
#define ASN1_TFLG_EXPTAG        (0x1 << 3)

#define ASN1_TFLG_TAG_MASK      (ASN1_TFLG_IMPTAG|ASN1_TFLG_EXPTAG)

#define ASN1_ITEM_TEMPLATE(mtype) \
        static const WOLFSSL_ASN1_TEMPLATE mtype##_member_data

#define ASN1_ITEM_TEMPLATE_END(mtype) \
    ; \
    const WOLFSSL_ASN1_ITEM mtype##_template_data = { \
            WOLFSSL_ASN1_OBJECT_TYPE, \
            &mtype##_member_data, \
            1, \
            0, \
            0 \
    };

#define ASN1_SEQUENCE(mtype) \
    static const WOLFSSL_ASN1_TEMPLATE mtype##_member_data[]

#define ASN1_SEQUENCE_END(mtype) \
    ; \
    const WOLFSSL_ASN1_ITEM mtype##_template_data = { \
            WOLFSSL_ASN1_SEQUENCE, \
            mtype##_member_data, \
            sizeof(mtype##_member_data) / sizeof(WOLFSSL_ASN1_TEMPLATE), \
            sizeof(mtype), \
            0 \
    }; \
    static WC_MAYBE_UNUSED const byte mtype##_FIRST_BYTE = \
        ASN_CONSTRUCTED | ASN_SEQUENCE;

/* This is what a ASN1_CHOICE type should look like
 *      typedef struct {
 *              int type;
 *              union {
 *                      ASN1_SOMETHING *opt1;
 *                      ASN1_SOMEOTHER *opt2;
 *              } value;
 *      } chname;
 */

#define ASN1_CHOICE(mtype) \
    static const WOLFSSL_ASN1_TEMPLATE mtype##_member_data[]

#define ASN1_CHOICE_END(mtype) \
    ; \
    const WOLFSSL_ASN1_ITEM mtype##_template_data = { \
            WOLFSSL_ASN1_CHOICE, \
            mtype##_member_data, \
            sizeof(mtype##_member_data) / sizeof(WOLFSSL_ASN1_TEMPLATE), \
            sizeof(mtype) ,\
            OFFSETOF(mtype, type) \
    };

#define ASN1_TYPE(type, member, tag, first_byte, exp, seq) \
    OFFSETOF(type, member), tag, first_byte, exp, seq

/* Function callbacks need to be defined immediately otherwise we will
 * incorrectly expand the type. Ex: ASN1_INTEGER -> WOLFSSL_ASN1_INTEGER */

#define ASN1_SIMPLE(type, member, member_type) \
    { (WolfsslAsn1NewCb)member_type##_new, \
      (WolfsslAsn1FreeCb)member_type##_free, \
      (WolfsslAsn1i2dCb)i2d_##member_type, \
      (WolfsslAsn1d2iCb)d2i_##member_type, \
      ASN1_TYPE(type, member, -1, 0, 0, 0) }

#define ASN1_IMP(type, member, member_type, tag) \
    { (WolfsslAsn1NewCb)member_type##_new, \
      (WolfsslAsn1FreeCb)member_type##_free, \
      (WolfsslAsn1i2dCb)i2d_##member_type, \
      (WolfsslAsn1d2iCb)d2i_##member_type, \
      ASN1_TYPE(type, member, tag, member_type##_FIRST_BYTE, 0, 0) }

#define ASN1_EXP(type, member, member_type, tag) \
    { (WolfsslAsn1NewCb)member_type##_new, \
      (WolfsslAsn1FreeCb)member_type##_free, \
      (WolfsslAsn1i2dCb)i2d_##member_type, \
      (WolfsslAsn1d2iCb)d2i_##member_type, \
      ASN1_TYPE(type, member, tag, 0, 1, 0) }

#define ASN1_SEQUENCE_OF(type, member, member_type) \
    { (WolfsslAsn1NewCb)member_type##_new, \
      (WolfsslAsn1FreeCb)member_type##_free, \
      (WolfsslAsn1i2dCb)i2d_##member_type, \
      (WolfsslAsn1d2iCb)d2i_##member_type, \
      ASN1_TYPE(type, member, -1, 0, 0, 1) }

#define ASN1_EXP_SEQUENCE_OF(type, member, member_type, tag) \
    { (WolfsslAsn1NewCb)member_type##_new, \
      (WolfsslAsn1FreeCb)member_type##_free, \
      (WolfsslAsn1i2dCb)i2d_##member_type, \
      (WolfsslAsn1d2iCb)d2i_##member_type, \
      ASN1_TYPE(type, member, tag, 0, 1, 1) }

#define ASN1_EX_TEMPLATE_TYPE(flags, tag, name, member_type) \
    { (WolfsslAsn1NewCb)member_type##_new, \
      (WolfsslAsn1FreeCb)member_type##_free, \
      (WolfsslAsn1i2dCb)i2d_##member_type, \
      (WolfsslAsn1d2iCb)d2i_##member_type, \
      0, (flags) & ASN1_TFLG_TAG_MASK ? (tag) : -1, 0, \
      !!((flags) & ASN1_TFLG_EXPLICIT), TRUE }

WOLFSSL_API void *wolfSSL_ASN1_item_new(const WOLFSSL_ASN1_ITEM *tpl);
WOLFSSL_API void wolfSSL_ASN1_item_free(void *obj,
        const WOLFSSL_ASN1_ITEM *item);
WOLFSSL_API int wolfSSL_ASN1_item_i2d(const void *src, byte **dest,
                                      const WOLFSSL_ASN1_ITEM *tpl);
WOLFSSL_API void* wolfSSL_ASN1_item_d2i(void** dst, const byte **src, long len,
        const WOLFSSL_ASN1_ITEM* item);

/* Need function declaration otherwise compiler complains */
/* // NOLINTBEGIN(readability-named-parameter,bugprone-macro-parentheses) */
#define IMPLEMENT_ASN1_FUNCTIONS(type) \
    type *type##_new(void); \
    type *type##_new(void){ \
        return (type*)wolfSSL_ASN1_item_new(&type##_template_data); \
    } \
    void type##_free(type *t); \
    void type##_free(type *t){ \
        wolfSSL_ASN1_item_free(t, &type##_template_data); \
    } \
    int i2d_##type(type *src, byte **dest); \
    int i2d_##type(type *src, byte **dest) \
    { \
        return wolfSSL_ASN1_item_i2d(src, dest, &type##_template_data); \
    } \
    type* d2i_##type(type **dst, const byte **src, long len); \
    type* d2i_##type(type **dst, const byte **src, long len) \
    { \
        return (type*)wolfSSL_ASN1_item_d2i((void**)dst, src, len, \
                &type##_template_data); \
    }
/* // NOLINTEND(readability-named-parameter,bugprone-macro-parentheses) */

#endif /* OPENSSL_ALL */

#define BN_to_ASN1_INTEGER          wolfSSL_BN_to_ASN1_INTEGER
#define ASN1_TYPE_set               wolfSSL_ASN1_TYPE_set
#define ASN1_TYPE_get               wolfSSL_ASN1_TYPE_get
#define ASN1_TYPE_new               wolfSSL_ASN1_TYPE_new
#define ASN1_TYPE_free              wolfSSL_ASN1_TYPE_free
#define i2d_ASN1_TYPE               wolfSSL_i2d_ASN1_TYPE

#endif /* WOLFSSL_ASN1_H_ */
