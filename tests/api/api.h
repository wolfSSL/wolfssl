/* api.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifndef WOLFCRYPT_TEST_API_H
#define WOLFCRYPT_TEST_API_H


#ifndef HEAP_HINT
    #define HEAP_HINT NULL
#endif


#define TEST_STRING    "Everyone gets Friday off."
#define TEST_STRING_SZ 25


/* Returns the result based on whether check is true.
 *
 * @param [in] check  Condition for success.
 * @return  When condition is true: TEST_SUCCESS.
 * @return  When condition is false: TEST_FAIL.
 */
#ifdef DEBUG_WOLFSSL_VERBOSE
#define XSTRINGIFY(s) STRINGIFY(s)
#define STRINGIFY(s)  #s
#define TEST_RES_CHECK(check) ({ \
    int _ret = (check) ? TEST_SUCCESS : TEST_FAIL; \
    if (_ret == TEST_FAIL) { \
        fprintf(stderr, " check \"%s\" at %d ", \
            XSTRINGIFY(check), __LINE__); \
    } \
    _ret; })
#else
#define TEST_RES_CHECK(check) \
    ((check) ? TEST_SUCCESS : TEST_FAIL)
#endif /* DEBUG_WOLFSSL_VERBOSE */


typedef struct testVector {
    const char* input;
    const char* output;
    size_t inLen;
    size_t outLen;
} testVector;


extern int testDevId;

#endif /* WOLFCRYPT_TEST_API_H */

