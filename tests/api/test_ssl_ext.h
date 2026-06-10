/* test_ssl_ext.h
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

#ifndef TESTS_API_SSL_EXT_H
#define TESTS_API_SSL_EXT_H

int test_wolfSSL_NoTicketTLSv12_ext(void);
int test_wolfSSL_CTX_UseMaxFragment_ext(void);
int test_wolfSSL_CTX_num_tickets_ext(void);
int test_wolfSSL_set1_groups_ext(void);
int test_wolfSSL_set1_groups_list_ext(void);
int test_wolfSSL_CTX_set_TicketHint_ext(void);
int test_wolfSSL_tlsext_max_fragment_length_ext(void);
int test_wolfSSL_DisableExtendedMasterSecret_ext(void);
int test_wolfSSL_set_tlsext_host_name_ext(void);
int test_wolfSSL_CTX_set_tlsext_servername_callback_ext(void);
int test_wolfSSL_set_tlsext_debug_arg_ext(void);
int test_wolfSSL_set_SessionTicket_cb_ext(void);
int test_wolfSSL_set1_curves_list_ext(void);
int test_wolfSSL_SecureResume_ext(void);
int test_wolfSSL_CTX_UseSecureRenegotiation_ext(void);
int test_wolfSSL_next_proto_cb_ext(void);
int test_wolfSSL_tlsext_status_exts_ids_ext(void);
int test_wolfSSL_SNI_GetFromBuffer_inval_ext(void);
int test_wolfSSL_UseTrustedCA_inval_ext(void);
int test_wolfSSL_UseMaxFragment_inval_ext(void);
int test_wolfSSL_set1_groups_inval_ext(void);
int test_wolfSSL_UseALPN_inval_ext(void);
int test_wolfSSL_ALPN_GetPeerProtocol_inval_ext(void);
int test_wolfSSL_CTX_set_TicketEncCb_inval_ext(void);
int test_wolfSSL_SessionTicket_inval_ext(void);
int test_wolfSSL_CTX_set_servername_arg_inval_ext(void);
int test_wolfSSL_CTX_set_alpn_protos_inval_ext(void);

#define TEST_SSL_EXT_DECLS                                                     \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_NoTicketTLSv12_ext),           \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_CTX_UseMaxFragment_ext),       \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_CTX_num_tickets_ext),          \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_set1_groups_ext),              \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_set1_groups_list_ext),         \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_CTX_set_TicketHint_ext),       \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_tlsext_max_fragment_length_ext),                     \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_DisableExtendedMasterSecret_ext),                    \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_set_tlsext_host_name_ext),     \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_CTX_set_tlsext_servername_callback_ext),             \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_set_tlsext_debug_arg_ext),     \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_set_SessionTicket_cb_ext),     \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_set1_curves_list_ext),         \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_SecureResume_ext),             \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_CTX_UseSecureRenegotiation_ext),                     \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_next_proto_cb_ext),            \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_tlsext_status_exts_ids_ext),                         \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_SNI_GetFromBuffer_inval_ext),                        \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_UseTrustedCA_inval_ext),       \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_UseMaxFragment_inval_ext),     \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_set1_groups_inval_ext),        \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_UseALPN_inval_ext),            \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_ALPN_GetPeerProtocol_inval_ext),                     \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_CTX_set_TicketEncCb_inval_ext),                      \
        TEST_DECL_GROUP("ssl_ext", test_wolfSSL_SessionTicket_inval_ext),      \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_CTX_set_servername_arg_inval_ext),                   \
        TEST_DECL_GROUP("ssl_ext",                                            \
            test_wolfSSL_CTX_set_alpn_protos_inval_ext)

#endif /* TESTS_API_SSL_EXT_H */
