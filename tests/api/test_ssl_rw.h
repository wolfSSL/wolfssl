/* test_ssl_rw.h
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

#ifndef TESTS_API_SSL_RW_H
#define TESTS_API_SSL_RW_H

#include <tests/api/api_decl.h>

int test_wolfSSL_send(void);
int test_wolfSSL_writev(void);
int test_wolfSSL_get_shutdown(void);
int test_wolfSSL_want(void);
int test_wolfSSL_pending_api(void);
int test_wolfSSL_rw_bad_args(void);
int test_wolfSSL_rw_info_callback(void);
int test_wolfSSL_write_ex_partial(void);
int test_wolfSSL_inject_app_data_ready(void);
int test_wolfSSL_shutdown_no_notify(void);
int test_wolfSSL_shutdown_repeat_after_done(void);
int test_wolfSSL_shutdown_flush_no_notify(void);
int test_wolfSSL_shutdown_quic_alert_refused(void);
int test_wolfSSL_SendUserCanceled_paths(void);
int test_wolfSSL_write_dup_err(void);

#define TEST_SSL_RW_DECLS                                                      \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_send),                          \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_writev),                        \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_get_shutdown),                  \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_want),                          \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_pending_api),                   \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_rw_bad_args),                   \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_rw_info_callback),              \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_write_ex_partial),              \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_inject_app_data_ready),         \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_shutdown_no_notify),            \
        TEST_DECL_GROUP("ssl_rw",                                              \
            test_wolfSSL_shutdown_repeat_after_done),                          \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_shutdown_flush_no_notify),      \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_shutdown_quic_alert_refused),   \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_SendUserCanceled_paths),        \
        TEST_DECL_GROUP("ssl_rw", test_wolfSSL_write_dup_err)

#endif /* TESTS_API_SSL_RW_H */
