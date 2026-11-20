/* test_idevid.h
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

#ifndef WOLFCRYPT_TEST_IDEVID_H
#define WOLFCRYPT_TEST_IDEVID_H

#include <tests/api/api_decl.h>

int test_idevid_cm_verify(void);
int test_idevid_date_limits(void);
int test_idevid_tls_client_auth(void);
int test_idevid_hw_module_name(void);
int test_idevid_hw_module_name_variants(void);
int test_idevid_subject_serial(void);
int test_idevid_unknown_ext_cb(void);
int test_idevid_compat_time(void);
int test_idevid_certgen(void);
int test_idevid_othername_trailing_data(void);

#define TEST_IDEVID_DECLS                                                   \
    TEST_DECL_GROUP("idevid", test_idevid_cm_verify),                       \
    TEST_DECL_GROUP("idevid", test_idevid_date_limits),                     \
    TEST_DECL_GROUP("idevid", test_idevid_tls_client_auth),                 \
    TEST_DECL_GROUP("idevid", test_idevid_hw_module_name),                  \
    TEST_DECL_GROUP("idevid", test_idevid_hw_module_name_variants),         \
    TEST_DECL_GROUP("idevid", test_idevid_subject_serial),                  \
    TEST_DECL_GROUP("idevid", test_idevid_unknown_ext_cb),                  \
    TEST_DECL_GROUP("idevid", test_idevid_compat_time),                     \
    TEST_DECL_GROUP("idevid", test_idevid_certgen),                         \
    TEST_DECL_GROUP("idevid", test_idevid_othername_trailing_data)

#endif /* WOLFCRYPT_TEST_IDEVID_H */
