/* test_dtls13.h
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

#ifndef TESTS_API_DTLS13_H
#define TESTS_API_DTLS13_H

#include <tests/api/api_decl.h>

/* DTLSv1.3-only tests. They live in their own translation unit and register
 * under the "dtls13" group; the helpers they share with the DTLS<=1.2 tests
 * are exported by tests/api/test_dtls.h. Each function is defined
 * unconditionally with the body (or the whole function via #else stub)
 * guarded by WOLFSSL_DTLS13. */
int test_dtls13_bad_epoch_ch(void);
int test_wolfSSL_dtls13_null_cipher(void);
int test_dtls13_frag_ch_pq(void);
int test_dtls13_frag_ch_pq_no_cookie(void);
int test_dtls_frag_ch(void);
int test_dtls13_frag_ch1_no_cookie(void);
int test_dtls13_no_cookie_handoff(void);
int test_dtls13_clear_ch_pool_api(void);
int test_dtls13_reassemble_ch_before_cookie_api(void);
int test_dtls13_frag_ch1_reassemble(void);
int test_dtls13_frag_ch2_cookie_not_first(void);
int test_dtls13_frag_ch2_cookie_frag_last(void);
int test_dtls13_frag_ch2_forged_first_frag(void);
int test_dtls13_frag_ch2_overlap_handoff(void);
int test_dtls13_frag_ch1_interleaved_peers(void);
int test_dtls13_frag_ch1_evict_oldest(void);
int test_dtls13_frag_ch1_over_bound(void);
int test_dtls13_frag_ch1_length_mismatch(void);
int test_dtls13_frag_past_end(void);
int test_dtls13_frag_ch2_planted_fragment(void);
int test_dtls13_frag_ch2_stale_fragment(void);
int test_dtls13_frag_ch1_no_cookie_conflict(void);
int test_dtls13_frag_ch1_bad_reassembled(void);
int test_dtls13_frag_ch2_verify_keeps_other_peers(void);
int test_dtls13_frag_ch_ctx_two_listeners(void);
int test_dtls13_frag_ch_ctx_survives_listener_free(void);
int test_dtls13_frag_ch_ctx_free_pending(void);
int test_dtls13_frag_ch1_ctx_shared_budget(void);
int test_dtls13_frag_ch_no_addr_dropped(void);
int test_dtls13_frag_ch1_ctx_budget_two_objects(void);
int test_dtls13_ch_whole_async_not_pooled(void);
int test_dtls13_ch_async_no_addr(void);
int test_dtls13_frag_ch2_ctx_handoff(void);
int test_dtls13_frag_ch2_ctx_cookie_mismatch(void);
int test_dtls13_frag_ch_ctx_set_ssl_ctx(void);
int test_dtls13_frag_ch1_ctx_stale_partial(void);
int test_dtls13_frag_ch_ctx_static_memory(void);
int test_dtls13_auth_drops_plaintext_frags(void);
int test_dtls13_frag_store_fatal(void);
int test_dtls13_clear_frees_rx_list(void);
int test_dtls13_frag_ch2_bad_cookie_dropped(void);
int test_dtls13_frag_ch2_dtls12_cookie(void);
int test_dtls13_ch_pool_threads(void);
int test_dtls13_ch_pool_shards_threads(void);
int test_dtls13_ch_pool_handshake_threads(void);
int test_dtls13_ctx_cookie_secret_handoff(void);
int test_dtls13_ctx_cookie_secret_set_ssl_ctx(void);
int test_dtls13_ctx_cookie_secret_threads(void);
int test_dtls13_ctx_cookie_secret_no_splice(void);
int test_dtls13_ctx_cookie_secret_after_random(void);
int test_dtls13_ch_pool_unit(void);
int test_dtls13_ch_pool_shards(void);
int test_dtls13_ch_pool_evict_own_shard(void);
int test_dtls13_ch_pool_evict_behind_own(void);
int test_dtls13_ch_pool_reserve_bound(void);
int test_dtls13_ch_pool_evict_for_bound(void);
int test_dtls13_ch_pool_evict_own_oldest(void);
int test_dtls13_ch_pool_bucket_cap(void);
int test_dtls13_ch_pool_peer_key(void);
int test_dtls13_ch_pool_max_age(void);
int test_dtls13_ch_pool_ctx_init(void);
int test_dtls13_ch_pool_max_bytes_api(void);
int test_dtls13_ch_pool_max_bytes(void);
int test_dtls_empty_keyshare_with_cookie(void);
int test_dtls13_missing_finished_client(void);
int test_dtls13_missing_finished_server(void);
int test_dtls13_finished_send_error_propagation(void);

/* DTLSv1.3-only tests moved from test_dtls.c (isolated from DTLS<=1.2 code,
 * none share helpers with non-DTLS13 tests). */
int test_dtls13_basic_connection_id(void);
int test_dtls13_hrr_want_write(void);
int test_dtls13_every_write_want_write(void);
int test_dtls13_epochs(void);
int test_dtls13_alert_with_pending_output(void);
int test_dtls13_ack_order(void);
int test_dtls13_ack_overflow(void);
int test_dtls13_ack_dup_write_counter(void);
int test_dtls13_ch2_rtx_no_ch1(void);
int test_dtls13_frag_ch2_with_ch1_rtx(void);
int test_dtls_srtp(void);
int test_dtls13_min_rtx_interval(void);
int test_dtls13_no_session_id_echo(void);
int test_dtls13_5_9_0_compat(void);
int test_dtls13_5_9_0_compat_bad_echo(void);
int test_dtls13_5_9_0_compat_empty_echo(void);
int test_dtls13_reuse_after_clear(void);
int test_dtls13_epoch_slot_reuse_replay(void);
int test_dtls13_epoch_slot_reuse_decrypt_epoch(void);
int test_dtls13_plaintext_ack_after_handshake(void);
int test_dtls13_plaintext_ack_during_handshake(void);
int test_dtls13_reset_clears_alert_history(void);
int test_dtls13_rtx_timeout_want_write(void);
int test_dtls13_rtx_timeout_want_write_read(void);
int test_dtls13_ignore_legacy_record_version(void);
int test_dtls13_ech_rejected_ticket_consumed(void);
int test_dtls13_update_keys_want_write(void);

#define TEST_DTLS13_DECLS                                                      \
    TEST_DECL_GROUP("dtls13", test_dtls13_bad_epoch_ch),                       \
    TEST_DECL_GROUP("dtls13", test_wolfSSL_dtls13_null_cipher),                \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_pq),                         \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_pq_no_cookie),               \
    TEST_DECL_GROUP("dtls13", test_dtls_frag_ch),                              \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_no_cookie),                 \
    TEST_DECL_GROUP("dtls13", test_dtls13_no_cookie_handoff),                  \
    TEST_DECL_GROUP("dtls13", test_dtls13_clear_ch_pool_api),                 \
    TEST_DECL_GROUP("dtls13", test_dtls13_reassemble_ch_before_cookie_api),    \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_reassemble),                \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_cookie_not_first),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_cookie_frag_last),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_forged_first_frag),         \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_overlap_handoff),           \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_interleaved_peers),         \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_evict_oldest),              \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_unit),                      \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_shards),                    \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_evict_own_shard),           \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_evict_behind_own),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_reserve_bound),            \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_evict_for_bound),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_evict_own_oldest),         \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_bucket_cap),               \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_peer_key),                  \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_max_age),                   \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_ctx_init),                  \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_max_bytes_api),             \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_max_bytes),                 \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_over_bound),                \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_length_mismatch),           \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_past_end),                      \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_planted_fragment),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_stale_fragment),            \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_no_cookie_conflict),        \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_bad_reassembled),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_verify_keeps_other_peers), \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_ctx_two_listeners),         \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_ctx_survives_listener_free), \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_ctx_free_pending),           \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_ctx_shared_budget),         \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_no_addr_dropped),           \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_ctx_budget_two_objects),   \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_whole_async_not_pooled),         \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_async_no_addr),                  \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_ctx_handoff),               \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_ctx_cookie_mismatch),       \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_ctx_set_ssl_ctx),            \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch1_ctx_stale_partial),        \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch_ctx_static_memory),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_auth_drops_plaintext_frags),       \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_store_fatal),                 \
    TEST_DECL_GROUP("dtls13", test_dtls13_clear_frees_rx_list),              \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_bad_cookie_dropped),      \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_dtls12_cookie),           \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_threads),                    \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_shards_threads),             \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch_pool_handshake_threads),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_ctx_cookie_secret_handoff),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_ctx_cookie_secret_set_ssl_ctx),      \
    TEST_DECL_GROUP("dtls13", test_dtls13_ctx_cookie_secret_threads),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_ctx_cookie_secret_no_splice),        \
    TEST_DECL_GROUP("dtls13", test_dtls13_ctx_cookie_secret_after_random),     \
    TEST_DECL_GROUP("dtls13", test_dtls_empty_keyshare_with_cookie),           \
    TEST_DECL_GROUP("dtls13", test_dtls13_missing_finished_client),            \
    TEST_DECL_GROUP("dtls13", test_dtls13_missing_finished_server),            \
    TEST_DECL_GROUP("dtls13", test_dtls13_finished_send_error_propagation),    \
    TEST_DECL_GROUP("dtls13", test_dtls13_basic_connection_id),                \
    TEST_DECL_GROUP("dtls13", test_dtls13_hrr_want_write),                     \
    TEST_DECL_GROUP("dtls13", test_dtls13_rtx_timeout_want_write),             \
    TEST_DECL_GROUP("dtls13", test_dtls13_rtx_timeout_want_write_read),        \
    TEST_DECL_GROUP("dtls13", test_dtls13_every_write_want_write),             \
    TEST_DECL_GROUP("dtls13", test_dtls13_epochs),                             \
    TEST_DECL_GROUP("dtls13", test_dtls13_alert_with_pending_output),          \
    TEST_DECL_GROUP("dtls13", test_dtls13_ack_order),                          \
    TEST_DECL_GROUP("dtls13", test_dtls13_ack_overflow),                       \
    TEST_DECL_GROUP("dtls13", test_dtls13_ack_dup_write_counter),              \
    TEST_DECL_GROUP("dtls13", test_dtls13_ch2_rtx_no_ch1),                     \
    TEST_DECL_GROUP("dtls13", test_dtls13_frag_ch2_with_ch1_rtx),              \
    TEST_DECL_GROUP("dtls13", test_dtls_srtp),                                 \
    TEST_DECL_GROUP("dtls13", test_dtls13_min_rtx_interval),                   \
    TEST_DECL_GROUP("dtls13", test_dtls13_no_session_id_echo),                 \
    TEST_DECL_GROUP("dtls13", test_dtls13_5_9_0_compat),                       \
    TEST_DECL_GROUP("dtls13", test_dtls13_5_9_0_compat_bad_echo),              \
    TEST_DECL_GROUP("dtls13", test_dtls13_5_9_0_compat_empty_echo),            \
    TEST_DECL_GROUP("dtls13", test_dtls13_reuse_after_clear),                  \
    TEST_DECL_GROUP("dtls13", test_dtls13_epoch_slot_reuse_replay),            \
    TEST_DECL_GROUP("dtls13", test_dtls13_epoch_slot_reuse_decrypt_epoch),     \
    TEST_DECL_GROUP("dtls13", test_dtls13_plaintext_ack_after_handshake),      \
    TEST_DECL_GROUP("dtls13", test_dtls13_plaintext_ack_during_handshake),     \
    TEST_DECL_GROUP("dtls13", test_dtls13_reset_clears_alert_history),         \
    TEST_DECL_GROUP("dtls13", test_dtls13_ignore_legacy_record_version),       \
    TEST_DECL_GROUP("dtls13", test_dtls13_ech_rejected_ticket_consumed),      \
    TEST_DECL_GROUP("dtls13", test_dtls13_update_keys_want_write)

#endif /* TESTS_API_DTLS13_H */
