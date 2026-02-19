/* linuxkm_memory.h
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

/* included by wolfssl/wolfcrypt/memory.h */

#ifndef LINUXKM_MEMORY_H
#define LINUXKM_MEMORY_H

enum wc_reloc_dest_segment {
    WC_R_SEG_NONE = 1,
    WC_R_SEG_TEXT,
    WC_R_SEG_RODATA,
    WC_R_SEG_RWDATA,
    WC_R_SEG_BSS,
    WC_R_SEG_OTHER
};

enum wc_reloc_type {
    WC_R_NONE = 1,
    WC_R_X86_64_32,
    WC_R_X86_64_32S,
    WC_R_X86_64_64,
    WC_R_X86_64_PC32,
    WC_R_X86_64_PLT32,
    WC_R_AARCH64_ABS32,
    WC_R_AARCH64_ABS64,
    WC_R_AARCH64_ADD_ABS_LO12_NC,
    WC_R_AARCH64_ADR_PREL_PG_HI21,
    WC_R_AARCH64_CALL26,
    WC_R_AARCH64_JUMP26,
    WC_R_AARCH64_LDST8_ABS_LO12_NC,
    WC_R_AARCH64_LDST16_ABS_LO12_NC,
    WC_R_AARCH64_LDST32_ABS_LO12_NC,
    WC_R_AARCH64_LDST64_ABS_LO12_NC,
    WC_R_AARCH64_PREL32,
    WC_R_ARM_ABS32,
    WC_R_ARM_PREL31,
    WC_R_ARM_REL32,
    WC_R_ARM_THM_CALL,
    WC_R_ARM_THM_JUMP11,
    WC_R_ARM_THM_JUMP24,
    WC_R_ARM_THM_MOVT_ABS,
    WC_R_ARM_THM_MOVW_ABS_NC
};

/* This structure is accessed natively by kernel module glue logic, and also
 * from outside by linux-fips-hash.c -- pack it, with explicit pad bits, to
 * remove all doubt about layout.
 */
struct __attribute__((packed)) wc_reloc_table_ent {
    unsigned int offset;
    unsigned int dest_offset;
    signed int dest_addend;
#define WC_RELOC_DEST_SEGMENT_BITS 3
    unsigned int dest_segment:WC_RELOC_DEST_SEGMENT_BITS;
#define WC_RELOC_TYPE_BITS 5
    unsigned int reloc_type:WC_RELOC_TYPE_BITS;
    unsigned int _pad_bits:(32 - (WC_RELOC_DEST_SEGMENT_BITS + WC_RELOC_TYPE_BITS));
};

#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)

/* full ELF fencepost representation, to allow wc_reloc_normalize_text() */

struct wc_reloc_table_segments {
    unsigned long start;
    unsigned long end;
    unsigned long reloc_tab_start;
    unsigned long reloc_tab_end;
    unsigned long reloc_tab_len_start;
    unsigned long reloc_tab_len_end;
    unsigned long text_start;
    unsigned long text_end;
#ifdef HAVE_FIPS
    unsigned long fips_text_start;
    unsigned long fips_text_end;
#endif /* HAVE_FIPS */
    unsigned long rodata_start;
    unsigned long rodata_end;
#ifdef HAVE_FIPS
    unsigned long fips_rodata_start;
    unsigned long fips_rodata_end;
    unsigned long verifyCore_start;
    unsigned long verifyCore_end;
#endif /* HAVE_FIPS */
    unsigned long data_start;
    unsigned long data_end;
    unsigned long bss_start;
    unsigned long bss_end;
    int text_is_live;
};

#ifdef HAVE_FIPS

#define WC_RELOC_TABLE_SEGMENTS_INITIALIZER { \
    .start = ~0UL,                            \
    .end = ~0UL,                              \
    .reloc_tab_start = ~0UL,                  \
    .reloc_tab_end = ~0UL,                    \
    .reloc_tab_len_start = ~0UL,              \
    .reloc_tab_len_end = ~0UL,                \
    .text_start = ~0UL,                       \
    .text_end = ~0UL,                         \
    .fips_text_start = ~0UL,                  \
    .fips_text_end = ~0UL,                    \
    .rodata_start = ~0UL,                     \
    .rodata_end = ~0UL,                       \
    .fips_rodata_start = ~0UL,                \
    .fips_rodata_end = ~0UL,                  \
    .verifyCore_start = ~0UL,                 \
    .verifyCore_end = ~0UL,                   \
    .data_start = ~0UL,                       \
    .data_end = ~0UL,                         \
    .bss_start = ~0UL,                        \
    .bss_end = 0,                             \
    .text_is_live = 0                         \
}

#else /* !HAVE_FIPS */

#define WC_RELOC_TABLE_SEGMENTS_INITIALIZER { \
    .start = ~0UL,                            \
    .end = ~0UL,                              \
    .reloc_tab_start = ~0UL,                  \
    .reloc_tab_end = ~0UL,                    \
    .reloc_tab_len_start = ~0UL,              \
    .reloc_tab_len_end = ~0UL,                \
    .text_start = ~0UL,                       \
    .text_end = ~0UL,                         \
    .rodata_start = ~0UL,                     \
    .rodata_end = ~0UL,                       \
    .data_start = ~0UL,                       \
    .data_end = ~0UL,                         \
    .bss_start = ~0UL,                        \
    .bss_end = 0,                             \
    .text_is_live = 0                         \
}

#endif /* !HAVE_FIPS */

struct wc_reloc_counts {
    int text;
    int rodata;
    int rwdata;
    int bss;
    int other;
};

#elif defined(HAVE_FIPS)

/* barebones FIPS fencepost representation -- no provision for
 * wc_reloc_normalize_text()
 */

struct wc_reloc_table_segments {
    unsigned long start;
    unsigned long end;
    unsigned long fips_text_start;
    unsigned long fips_text_end;
    unsigned long fips_rodata_start;
    unsigned long fips_rodata_end;
    unsigned long verifyCore_start;
    unsigned long verifyCore_end;
};

#define WC_RELOC_TABLE_SEGMENTS_INITIALIZER { \
    .start = ~0UL,                            \
    .end = ~0UL,                              \
    .fips_text_start = ~0UL,                  \
    .fips_text_end = ~0UL,                    \
    .fips_rodata_start = ~0UL,                \
    .fips_rodata_end = ~0UL,                  \
    .verifyCore_start = ~0UL,                 \
    .verifyCore_end = ~0UL                    \
}

struct wc_reloc_counts {
    int dummy;
};

#endif /* !WC_SYM_RELOC_TABLES && HAVE_FIPS */

#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)

WOLFSSL_API ssize_t wc_reloc_normalize_text(
    const byte *text_in,
    size_t text_in_len,
    byte *text_out,
    ssize_t *cur_index_p,
    const struct wc_reloc_table_segments *seg_map,
    struct wc_reloc_counts *reloc_counts);

#endif /* WC_SYM_RELOC_TABLES || WC_SYM_RELOC_TABLES_SUPPORT */

#ifdef HAVE_FIPS

#if defined(WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE) || defined(WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE_SUPPORT)
    typedef int (*wc_fips_verifyCore_hmac_setkey_fn)(void *ctx, const byte *key, word32 key_len);
    typedef int (*wc_fips_verifyCore_hmac_update_fn)(void *ctx, const byte *in, word32 in_len);
    typedef int (*wc_fips_verifyCore_hmac_final_fn)(void *ctx, byte *out, word32 out_sz);

    WOLFSSL_API int wc_fips_generate_hash(
        const struct wc_reloc_table_segments *seg_map,
        word32 digest_size,
        const char *hmac_key_base16,
        void *hmac_ctx,
        wc_fips_verifyCore_hmac_setkey_fn hmac_setkey,
        wc_fips_verifyCore_hmac_update_fn hmac_update,
        wc_fips_verifyCore_hmac_final_fn hmac_final,
        char *out,
        word32 *out_size,
        struct wc_reloc_counts *reloc_counts);
#endif

#endif /* HAVE_FIPS */

#endif /* LINUXKM_MEMORY_H */
