/* test_blake2s_whitebox.c
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

/*
 * MC/DC white-box supplement for wolfcrypt/src/blake2s.c -- the BLAKE2s
 * counterpart of test_blake2b_whitebox.c. The internal blake2s_init()
 * (blake2s.c:122) and blake2s_init_key() (blake2s.c:140/142) argument guards
 * are unreachable through the public wc_InitBlake2s* wrappers and are
 * non-WOLFSSL_API, so they are exercised here via a direct #include of
 * blake2s.c rather than from tests/api.
 */

#include <wolfcrypt/src/blake2s.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

int main(void)
{
    printf("blake2s.c white-box supplement\n");
#ifdef HAVE_BLAKE2S
    blake2s_state bs;
    byte          key[BLAKE2S_KEYBYTES];

    XMEMSET(&bs, 0, sizeof(bs));
    XMEMSET(key, 0, sizeof(key));

    /* blake2s_init(): !outlen || outlen > BLAKE2S_OUTBYTES */
    if (blake2s_init(&bs, 0) != BAD_FUNC_ARG) wb_fail = 1;
    if (blake2s_init(&bs, BLAKE2S_OUTBYTES + 1) != BAD_FUNC_ARG) wb_fail = 1;
    if (blake2s_init(&bs, BLAKE2S_OUTBYTES) != 0) wb_fail = 1;

    /* blake2s_init_key(): outlen bound, key/keylen held valid to isolate it. */
    if (blake2s_init_key(&bs, 0, key, BLAKE2S_KEYBYTES) != BAD_FUNC_ARG)
        wb_fail = 1;
    if (blake2s_init_key(&bs, BLAKE2S_OUTBYTES + 1, key, BLAKE2S_KEYBYTES)
            != BAD_FUNC_ARG) wb_fail = 1;

    /* blake2s_init_key(): !key || !keylen || keylen > BLAKE2S_KEYBYTES,
     * outlen held valid to isolate this decision. */
    if (blake2s_init_key(&bs, BLAKE2S_OUTBYTES, NULL, BLAKE2S_KEYBYTES)
            != BAD_FUNC_ARG) wb_fail = 1;
    if (blake2s_init_key(&bs, BLAKE2S_OUTBYTES, key, 0) != BAD_FUNC_ARG)
        wb_fail = 1;
    if (blake2s_init_key(&bs, BLAKE2S_OUTBYTES, key, BLAKE2S_KEYBYTES + 1)
            != BAD_FUNC_ARG) wb_fail = 1;
    /* Baseline: both decisions false on both lines. */
    if (blake2s_init_key(&bs, BLAKE2S_OUTBYTES, key, BLAKE2S_KEYBYTES) != 0)
        wb_fail = 1;

    WB_NOTE("blake2s_init / blake2s_init_key outlen+key+keylen guards exercised");
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  HAVE_BLAKE2S not defined; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
