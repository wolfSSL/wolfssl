/* linuxkm_memory.c
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

/* included by wolfcrypt/src/memory.c */

#if defined(WOLFSSL_LINUXKM) && defined(WC_SYM_RELOC_TABLES) && defined(CONFIG_FORTIFY_SOURCE)
/* needed because FORTIFY_SOURCE inline implementations call fortify_panic(). */
void __my_fortify_panic(const char *name) {
    pr_emerg("__my_fortify_panic in %s\n", name);
    BUG();
}
#endif

#ifdef DEBUG_LINUXKM_PIE_SUPPORT
    #define RELOC_DEBUG_PRINTF(fmt, ...) WOLFSSL_DEBUG_PRINTF("%s L %d: " fmt, __FILE__, __LINE__, ## __VA_ARGS__)
#else
    #define RELOC_DEBUG_PRINTF(...) WC_DO_NOTHING
#endif

#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)

static const struct reloc_layout_ent {
    const char *name;
    word64 mask;
    word64 width;
    word64 is_signed:1;
    word64 is_relative:1;
    word64 is_pages:1;
    word64 is_pair_lo:1;
    word64 is_pair_hi:1;
} reloc_layouts[] = {
    [WC_R_X86_64_32]                  = { "R_X86_64_32",                                                ~0UL, 32, .is_signed = 0, .is_relative = 0 },
    [WC_R_X86_64_32S]                 = { "R_X86_64_32S",                                               ~0UL, 32, .is_signed = 1, .is_relative = 0 },
    [WC_R_X86_64_64]                  = { "R_X86_64_64",                                                ~0UL, 64, .is_signed = 0, .is_relative = 0 },
    [WC_R_X86_64_PC32]                = { "R_X86_64_PC32",                                              ~0UL, 32, .is_signed = 1, .is_relative = 1 },
    [WC_R_X86_64_PLT32]               = { "R_X86_64_PLT32",                                             ~0UL, 32, .is_signed = 1, .is_relative = 1 },
    [WC_R_AARCH64_ABS32]              = { "R_AARCH64_ABS32",                                            ~0UL, 32, .is_signed = 1, .is_relative = 0, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_AARCH64_ABS64]              = { "R_AARCH64_ABS64",                                            ~0UL, 64, .is_signed = 1, .is_relative = 0, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_AARCH64_ADD_ABS_LO12_NC]    = { "R_AARCH64_ADD_ABS_LO12_NC",    0b00000000001111111111110000000000, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 1, .is_pair_hi = 0 },
    [WC_R_AARCH64_ADR_PREL_PG_HI21]   = { "R_AARCH64_ADR_PREL_PG_HI21",   0b01100000111111111111111111100000, 32, .is_signed = 1, .is_relative = 1, .is_pages = 1, .is_pair_lo = 0, .is_pair_hi = 1 },
    [WC_R_AARCH64_CALL26]             = { "R_AARCH64_CALL26",             0b00000011111111111111111111111111, 32, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_AARCH64_JUMP26]             = { "R_AARCH64_JUMP26",             0b00000011111111111111111111111111, 32, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_AARCH64_LDST8_ABS_LO12_NC]  = { "R_AARCH64_LDST8_ABS_LO12_NC",  0b00000000001111111111110000000000, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 1, .is_pair_hi = 0 },
    [WC_R_AARCH64_LDST16_ABS_LO12_NC] = { "R_AARCH64_LDST16_ABS_LO12_NC", 0b00000000001111111111110000000000, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 1, .is_pair_hi = 0 },
    [WC_R_AARCH64_LDST32_ABS_LO12_NC] = { "R_AARCH64_LDST32_ABS_LO12_NC", 0b00000000001111111111110000000000, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 1, .is_pair_hi = 0 },
    [WC_R_AARCH64_LDST64_ABS_LO12_NC] = { "R_AARCH64_LDST64_ABS_LO12_NC", 0b00000000001111111111110000000000, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 1, .is_pair_hi = 0 },
    [WC_R_AARCH64_PREL32]             = { "R_AARCH64_PREL32",                                           ~0UL, 32, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_ARM_ABS32]                  = { "R_ARM_ABS32",                                                ~0UL, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_ARM_PREL31]                 = { "R_ARM_PREL31",                 0b01111111111111111111111111111111, 32, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_ARM_REL32]                  = { "R_ARM_REL32",                                                ~0UL, 32, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_ARM_THM_CALL]               = { "R_ARM_THM_CALL",               0b00000111111111110010111111111111, 32, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_ARM_THM_JUMP24]             = { "R_ARM_THM_JUMP24",             0b00000111111111110010111111111111, 32, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_ARM_THM_JUMP11]             = { "R_ARM_THM_JUMP11",             0b00000000000000000000011111111111, 16, .is_signed = 1, .is_relative = 1, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 0 },
    [WC_R_ARM_THM_MOVT_ABS]           = { "R_ARM_THM_MOVT_ABS",           0b00000100000011110111000011111111, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 0, .is_pair_hi = 1 },
    [WC_R_ARM_THM_MOVW_ABS_NC]        = { "R_ARM_THM_MOVW_ABS_NC",        0b00000100000011110111000011111111, 32, .is_signed = 0, .is_relative = 0, .is_pages = 0, .is_pair_lo = 1, .is_pair_hi = 0 }
    };

static inline long find_reloc_tab_offset(
    const struct wc_reloc_table_ent reloc_tab[],
    word32 reloc_tab_len,
    size_t seg_in_offset)
{
    long ret;
    unsigned long hop;

    if (seg_in_offset >= (size_t)reloc_tab[reloc_tab_len - 1].offset) {
        RELOC_DEBUG_PRINTF("ERROR: %s failed.\n", __FUNCTION__);
        return BAD_FUNC_ARG;
    }

    if (reloc_tab_len <= 1) {
        /* empty relocation table. */
        return 0;
    }
    for (ret = 0,
             hop = reloc_tab_len >> 1;
         hop;
         hop >>= 1)
    {
        if (seg_in_offset == (size_t)reloc_tab[ret].offset)
            break;
        else if (seg_in_offset > (size_t)reloc_tab[ret].offset)
            ret += hop;
        else if (ret)
            ret -= hop;
    }

    while ((ret < (long)reloc_tab_len - 1) &&
           ((size_t)reloc_tab[ret].offset < seg_in_offset))
        ++ret;

    while ((ret > 0) &&
           ((size_t)reloc_tab[ret - 1].offset >= seg_in_offset))
        --ret;

#ifdef DEBUG_LINUXKM_PIE_SUPPORT
    if (ret < 0)
        RELOC_DEBUG_PRINTF("ERROR: %s returning %ld.\n", __FUNCTION__, ret);
#endif
    return ret;
}

/* Note we are not currently accommodating endianness conflicts between the
 * build and target host, but if we were, these macros would byte swap.
 * Currently, we detect and fail early on endianness conflicts.
 */
#define wc_get_unaligned(v) ({ typeof(*(v)) _v_aligned; XMEMCPY((void *)&_v_aligned, (void *)(v), sizeof _v_aligned); _v_aligned; })
#define wc_put_unaligned(v, v_out) do { typeof(v) _v = (v); XMEMCPY((void *)(v_out), (void *)&_v, sizeof(typeof(*(v_out)))); } while (0)

ssize_t wc_reloc_normalize_segment(
    const byte *seg_in,
    size_t *seg_in_out_len,
    byte *seg_out,
    ssize_t *cur_index_p,
    const struct wc_reloc_table_segments *seg_map,
    struct wc_reloc_counts *reloc_counts)
{
    ssize_t i;
    size_t seg_in_offset;
    const struct wc_reloc_table_ent *last_reloc; /* for error-checking order in reloc_tab[] */
    int n_text_r = 0, n_rodata_r = 0, n_rwdata_r = 0, n_bss_r = 0, n_other_r = 0, n_oob_r = 0;
    const struct wc_reloc_table_ent *reloc_tab;
    word32 reloc_tab_len;
    uintptr_t src_seg_start;
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
    uintptr_t src_seg_end;
    const char *src_seg_name;
#endif

    if (*seg_in_out_len == 0)
        return BAD_FUNC_ARG;

    if (((uintptr_t)seg_in >= seg_map->text_start) &&
        ((uintptr_t)(seg_in + *seg_in_out_len) <= seg_map->text_end))
    {
        reloc_tab = (const struct wc_reloc_table_ent *)seg_map->text_reloc_tab.start;
        reloc_tab_len = *(const word32 *)seg_map->text_reloc_tab.len_start;
        src_seg_start = seg_map->text_start;
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
        src_seg_end = seg_map->text_end;
        src_seg_name = "text";
#endif
    }
    else if (((uintptr_t)seg_in >= seg_map->rodata_start) &&
        ((uintptr_t)(seg_in + *seg_in_out_len) <= seg_map->rodata_end))
    {
        reloc_tab = (const struct wc_reloc_table_ent *)seg_map->rodata_reloc_tab.start;
        reloc_tab_len = *(const word32 *)seg_map->rodata_reloc_tab.len_start;
        src_seg_start = seg_map->rodata_start;
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
        src_seg_end = seg_map->rodata_end;
        src_seg_name = "rodata";
#endif
    }
    else
    {
        RELOC_DEBUG_PRINTF("ERROR: %s returning BAD_FUNC_ARG with span %llx-%llx versus text %llx-%llx and rodata %llx-%llx.\n",
               __FUNCTION__,
               (unsigned long long)(uintptr_t)seg_in,
               (unsigned long long)(uintptr_t)(seg_in + *seg_in_out_len),
               (unsigned long long)seg_map->text_start,
               (unsigned long long)seg_map->text_end,
               (unsigned long long)seg_map->rodata_start,
               (unsigned long long)seg_map->rodata_end);
        return BAD_FUNC_ARG;
    }

    seg_in_offset = (uintptr_t)seg_in - src_seg_start;

    if (cur_index_p)
        i = *cur_index_p;
    else
        i = -1;

    if (i == -1)
        i = find_reloc_tab_offset(reloc_tab, reloc_tab_len, seg_in_offset);

    if (i < 0)
        return i;

    WC_SANITIZE_DISABLE();
    memcpy(seg_out, seg_in, *seg_in_out_len);
    WC_SANITIZE_ENABLE();

    /* note, if there are no relocations in the src seg, the loop isn't entered
     * at all, and we return without further ado.
     */
    for (last_reloc = &reloc_tab[i > 0 ? i-1 : 0];
         (size_t)i < reloc_tab_len - 1;
         ++i)
    {
        const struct wc_reloc_table_ent *next_reloc = &reloc_tab[i];
        enum wc_reloc_dest_segment dest_seg;
        uintptr_t dest_seg_start;
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
        uintptr_t dest_seg_end;
        const char *dest_seg_name;
#endif
        word64 reloc_buf = 0;
        const struct reloc_layout_ent *layout;
        unsigned int next_reloc_rel;

        if (next_reloc->dest_segment == WC_R_SEG_NONE) {
            RELOC_DEBUG_PRINTF("BUG: missing dest segment for relocation at reloc_tab[%zd]\n", i);
            continue;
        }

        if (last_reloc->offset > next_reloc->offset) {
            RELOC_DEBUG_PRINTF("BUG: out-of-order offset found at reloc_tab[%zd]: %u > %u\n",
                   i, last_reloc->offset, next_reloc->offset);
            return BAD_FUNC_ARG;
        }

        last_reloc = next_reloc;

        if (next_reloc->reloc_type >= (sizeof reloc_layouts / sizeof reloc_layouts[0])) {
            RELOC_DEBUG_PRINTF("BUG: unknown relocation type %u found at reloc_tab[%zd]\n",
                   next_reloc->reloc_type, i);
                return BAD_FUNC_ARG;
        }

        layout = &reloc_layouts[next_reloc->reloc_type];

        switch (layout->width) {
        case 32:
        case 64:
        case 16:
            break;
        default:
            RELOC_DEBUG_PRINTF("BUG: unexpected relocation width %llu found at reloc_tab[%lld], reloc type %u\n",
                   (unsigned long long)layout->width, (long long)i, next_reloc->reloc_type);
            return BAD_FUNC_ARG;
        }

        /* provisionally assign the destination segment from the reloc record --
         * it may wind up getting overridden later if things don't go as
         * expected.
         */
        dest_seg = next_reloc->dest_segment;

        /* next_reloc_rel is the offset of the relocation relative to the start
         * of the current text chunk (seg_in).  i.e., seg_in + next_reloc_rel
         * is the start of the relocation.
         */
        next_reloc_rel = next_reloc->offset - seg_in_offset;

        if (next_reloc_rel >= *seg_in_out_len) {
            /* no more relocations in this buffer. */
            break;
        }

        if ((*seg_in_out_len < WC_BITS_TO_BYTES(layout->width)) ||
            (next_reloc_rel > *seg_in_out_len - WC_BITS_TO_BYTES(layout->width)))
        {
            /* relocation straddles buffer at end -- caller will try again with
             * that relocation at the start.
             */
            *seg_in_out_len = next_reloc_rel;
            break;
        }

        /* set reloc_buf to the address bits from the live text segment.  on
         * ARM, this will often also pull in some opcode bits, which we mask out.
         */
        if (layout->is_signed) {
            /* Note, the intermediate cast to sword64 is necessary to
             * sign-extend the value to 64 bits before unsigned
             * reinterpretation.  Normalization later relies on this.
             */
            switch (layout->width) {
            case 32:
                reloc_buf = (word64)(sword64)(wc_get_unaligned((sword32 *)&seg_out[next_reloc_rel]) & (sword32)layout->mask);
                break;
            case 64:
                reloc_buf = (word64)(sword64)(wc_get_unaligned((sword64 *)&seg_out[next_reloc_rel]) & (sword64)layout->mask);
                break;
            case 16:
                reloc_buf = (word64)(sword64)(wc_get_unaligned((sword16 *)&seg_out[next_reloc_rel]) & (sword16)layout->mask);
                break;
            }
        }
        else {
            switch (layout->width) {
            case 32:
                reloc_buf = (word64)(wc_get_unaligned((word32 *)&seg_out[next_reloc_rel]) & (word32)layout->mask);
                break;
            case 64:
                reloc_buf = (word64)(wc_get_unaligned((word64 *)&seg_out[next_reloc_rel]) & layout->mask);
                break;
            case 16:
                reloc_buf = (word64)(wc_get_unaligned((word16 *)&seg_out[next_reloc_rel]) & (word16)layout->mask);
                break;
            }
        }

        switch (dest_seg) {
        case WC_R_SEG_TEXT:
            dest_seg_start = seg_map->text_start;
            ++n_text_r;
            #ifdef DEBUG_LINUXKM_PIE_SUPPORT
            dest_seg_end = seg_map->text_end;
            dest_seg_name = "text";
            #endif
            break;
        case WC_R_SEG_RODATA:
            dest_seg_start = seg_map->rodata_start;
            ++n_rodata_r;
            #ifdef DEBUG_LINUXKM_PIE_SUPPORT
            dest_seg_end = seg_map->rodata_end;
            dest_seg_name = "rodata";
            #endif
            break;
        case WC_R_SEG_RWDATA:
            dest_seg_start = seg_map->data_start;
            ++n_rwdata_r;
            #ifdef DEBUG_LINUXKM_PIE_SUPPORT
            dest_seg_end = seg_map->data_end;
            dest_seg_name = "data";
            #endif
            break;
        case WC_R_SEG_BSS:
            dest_seg_start = seg_map->bss_start;
            ++n_bss_r;
            #ifdef DEBUG_LINUXKM_PIE_SUPPORT
            dest_seg_end = seg_map->bss_end;
            dest_seg_name = "bss";
            #endif
            break;
        default:
        case WC_R_SEG_NONE:
            dest_seg = WC_R_SEG_OTHER;
            FALL_THROUGH;
        case WC_R_SEG_OTHER:
            dest_seg_start = 0;
            #ifdef DEBUG_LINUXKM_PIE_SUPPORT
            dest_seg_end = 0;
            dest_seg_name = "other";
            #endif
            break;
        }

        switch (next_reloc->reloc_type) {
        case WC_R_X86_64_PC32:
        case WC_R_X86_64_PLT32:
        case WC_R_X86_64_32:
        case WC_R_X86_64_32S:
        case WC_R_X86_64_64:

            if (dest_seg != WC_R_SEG_OTHER) {
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
                word64 raw_dest_addr = reloc_buf;
#endif
                if (seg_map->text_is_live) {
                    /* note these normalize to the base address of the
                     * destination symbol, S, and removes the addend A, which is
                     * baked into the reloc_tab for each relocation.
                     */
                    if (layout->is_relative)
                        reloc_buf = reloc_buf + (uintptr_t)next_reloc->offset - (uintptr_t)next_reloc->dest_addend - (dest_seg_start - src_seg_start);
                    else
                        reloc_buf = reloc_buf - dest_seg_start - (uintptr_t)next_reloc->dest_addend;
                }
                else {
                    reloc_buf = (word64)next_reloc->dest_offset;
                }
#ifdef DEBUG_LINUXKM_PIE_SUPPORT
                if (reloc_buf >= dest_seg_end - dest_seg_start) {
                    ++n_oob_r;
                    RELOC_DEBUG_PRINTF("WARNING: normalized value is out of bounds (%s0x%llx) at index %lld, %s offset 0x%x, reloc type %s, "
                                         "src seg .%s_wolfcrypt, dest seg .%s_wolfcrypt, offset from src to dest segment %s0x%llx, raw dest addr %s0x%llx, "
                                         "seg span 0x%llx - 0x%llx, seg size 0x%llx, src seg 0x%llx-0x%llx\n",
                                         (long long)reloc_buf < 0 ? "-" : "",
                                         (long long)reloc_buf < 0 ? -(long long)reloc_buf : (long long)reloc_buf,
                                         (long long)i,
                                         src_seg_name,
                                         next_reloc->offset,
                                         layout->name,
                                         src_seg_name,
                                         dest_seg_name,
                                         dest_seg_start < src_seg_start ? "-" : "+",
                                         dest_seg_start < src_seg_start ? (unsigned long long)src_seg_start - dest_seg_start : dest_seg_start - (unsigned long long)src_seg_start,
                                         (layout->is_signed && ((long long)raw_dest_addr < 0)) ? "-" : "",
                                         (layout->is_signed && ((long long)raw_dest_addr < 0)) ? (unsigned long long)-(long long)raw_dest_addr : raw_dest_addr,
                                         (unsigned long long)dest_seg_start,
                                         (unsigned long long)dest_seg_end,
                                         (unsigned long long)(dest_seg_end - dest_seg_start),
                                       (unsigned long long)src_seg_start, (unsigned long long)src_seg_end);
                }
#endif
            }

            break;

        case WC_R_ARM_ABS32:
        case WC_R_ARM_PREL31:
        case WC_R_ARM_REL32:
        case WC_R_ARM_THM_CALL:
        case WC_R_ARM_THM_JUMP11:
        case WC_R_ARM_THM_JUMP24:
        case WC_R_ARM_THM_MOVT_ABS:
        case WC_R_ARM_THM_MOVW_ABS_NC:
            /* Don't attempt to reconstruct ARM destination addresses -- just
             * normalize to zero.  They can be reconstructed using the
             * parameters in reloc_layouts[] and reloc_tab[] but it's very
             * fidgety.
             */
            reloc_buf = 0;
            break;

        case WC_R_AARCH64_ABS32:
        case WC_R_AARCH64_ABS64:
        case WC_R_AARCH64_ADD_ABS_LO12_NC:
        case WC_R_AARCH64_ADR_PREL_PG_HI21:
        case WC_R_AARCH64_CALL26:
        case WC_R_AARCH64_JUMP26:
        case WC_R_AARCH64_LDST16_ABS_LO12_NC:
        case WC_R_AARCH64_LDST32_ABS_LO12_NC:
        case WC_R_AARCH64_LDST64_ABS_LO12_NC:
        case WC_R_AARCH64_LDST8_ABS_LO12_NC:
        case WC_R_AARCH64_PREL32:

            /* Don't attempt to reconstruct ARM destination addresses -- just
             * normalize to zero.  They can be reconstructed using the
             * parameters in reloc_layouts[] and reloc_tab[] but it's very
             * fidgety.
             */
            reloc_buf = 0;
            break;

        default:
            RELOC_DEBUG_PRINTF("BUG: unrecognized relocation type %u in reloc record %zu, %s offset 0x%x\n",
                               (unsigned)next_reloc->reloc_type, i, src_seg_name, reloc_tab[i].offset);
            ++n_oob_r;
            dest_seg = WC_R_SEG_OTHER;
        }

        if (dest_seg == WC_R_SEG_OTHER) {
            /* relocation referring to non-wolfcrypt segment -- these can only
             * be stabilized by zeroing them.
             */
            reloc_buf = 0;

            ++n_other_r;
            RELOC_DEBUG_PRINTF("found non-wolfcrypt relocation at index %lld, %s offset 0x%x.\n",
                               (long long)i, src_seg_name, reloc_tab[i].offset);
        }

        /* xor in a label identifying the dest segment and reloc type. */
        reloc_buf ^= dest_seg << (layout->width - WC_RELOC_DEST_SEGMENT_BITS);
        reloc_buf ^= next_reloc->reloc_type << (layout->width - (WC_RELOC_DEST_SEGMENT_BITS + WC_RELOC_TYPE_BITS));

        /* write the modified reloc_buf to the destination buffer. */
        switch (layout->width) {
        case 32:
            wc_put_unaligned((word32)reloc_buf, (word32 *)&seg_out[next_reloc_rel]);
            break;
        case 64:
            wc_put_unaligned(reloc_buf, (word64 *)&seg_out[next_reloc_rel]);
            break;
        case 16:
            wc_put_unaligned((word16)reloc_buf, (word16 *)&seg_out[next_reloc_rel]);
            break;
        }
    }

    if (reloc_counts) {
        reloc_counts->text += n_text_r;
        reloc_counts->rodata += n_rodata_r;
        reloc_counts->rwdata += n_rwdata_r;
        reloc_counts->bss += n_bss_r;
        reloc_counts->other += n_other_r;
    }

    if ((n_other_r > 0) || (n_oob_r > 0))
        RELOC_DEBUG_PRINTF("seg_in=%llx relocs=%d/%d/%d/%d/%d/%d ret = %llu\n",
                  (unsigned long long)(uintptr_t)seg_in, n_text_r, n_rodata_r,
                  n_rwdata_r, n_bss_r, n_other_r, n_oob_r,
                  (unsigned long long)*seg_in_out_len);

    if (cur_index_p)
        *cur_index_p = i;

    return (ssize_t)*seg_in_out_len;
}

#endif /* WC_SYM_RELOC_TABLES || WC_SYM_RELOC_TABLES_SUPPORT */

#ifdef HAVE_FIPS

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE

#include <wolfssl/wolfcrypt/fips_test.h>
#ifndef MAX_FIPS_DATA_SZ
    #define MAX_FIPS_DATA_SZ 10000000
#endif
#ifndef MAX_FIPS_CODE_SZ
    #define MAX_FIPS_CODE_SZ 10000000
#endif

#include <wolfssl/wolfcrypt/coding.h>

#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

/* failsafe definitions for FIPS <5.3 */
#ifndef FIPS_IN_CORE_DIGEST_SIZE
    #ifndef NO_SHA256
        #define FIPS_IN_CORE_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA256
    #elif defined(WOLFSSL_SHA384)
        #define FIPS_IN_CORE_DIGEST_SIZE WC_SHA384_DIGEST_SIZE
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA384
    #elif defined(WOLFSSL_SHA512)
        #define FIPS_IN_CORE_DIGEST_SIZE WC_SHA512_DIGEST_SIZE
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA512
    #else
        #error Unsupported FIPS hash alg.
    #endif
#endif

#ifndef FIPS_IN_CORE_KEY_SZ
    #define FIPS_IN_CORE_KEY_SZ FIPS_IN_CORE_DIGEST_SIZE
#endif
#ifndef FIPS_IN_CORE_VERIFY_SZ
    #define FIPS_IN_CORE_VERIFY_SZ FIPS_IN_CORE_DIGEST_SIZE
#endif

/* wc_fips_generate_hash() is the high level entry point to the supplementary
 * FIPS integrity hash calculation facility, used for offline hash calculation
 * (particularly for kernel module builds), and for the
 * WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE mechanism in the kernel module.
 *
 * The seg_map describes the layout of the module, including its precomputed
 * relocation table and its FIPS fenceposts.  For
 * WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE, seg_map is a static const in
 * module_hooks.c, but for offline calculation, readelf is used in
 * linuxkm-fips-hash-wrapper.sh to extract the values to pass to
 * linuxkm-fips-hash.
 *
 * The HMAC callback pointers are generic, but have wolfCrypt-like argument
 * structure -- for live WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE calls, they
 * point to wrappers around native Linux kernel implementations, but for
 * linuxkm-fips-hash, they point to wrappers around native wolfCrypt
 * implementations.
 */

int wc_fips_generate_hash(
    const struct wc_reloc_table_segments *seg_map,
    word32 digest_size,
    const char *hmac_key_base16,
    void *hmac_ctx,
    wc_fips_verifyCore_hmac_setkey_fn hmac_setkey,
    wc_fips_verifyCore_hmac_update_fn hmac_update,
    wc_fips_verifyCore_hmac_final_fn hmac_final,
    char *out,
    word32 *out_size,
    struct wc_reloc_counts *reloc_counts)
{
    word32 binCoreSz  = FIPS_IN_CORE_KEY_SZ;
    int ret;
    byte *hash = NULL;
    byte *binCoreKey = NULL;

#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)
    if (seg_map->text_is_live) {
        if ((seg_map->text_reloc_tab.start == 0) ||
            (seg_map->text_reloc_tab.len_start == 0))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        if ((seg_map->rodata_reloc_tab.start == 0) ||
            (seg_map->rodata_reloc_tab.len_start == 0))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
    }
    else {
        if ((seg_map->text_reloc_tab.end == 0) ||
            (seg_map->text_reloc_tab.len_end == 0))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        if ((seg_map->rodata_reloc_tab.end == 0) ||
            (seg_map->rodata_reloc_tab.len_end == 0))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
    }
#endif

    if (((seg_map->end > 0) && (seg_map->start >= seg_map->end)) ||
        (seg_map->fips_text_start >= seg_map->fips_text_end) ||
        (seg_map->fips_rodata_start >= seg_map->fips_rodata_end)
#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)
        ||
        ((seg_map->text_reloc_tab.end != 0) && (seg_map->text_reloc_tab.start >= seg_map->text_reloc_tab.end)) ||
        ((seg_map->text_reloc_tab.len_end != 0) && (seg_map->text_reloc_tab.len_start >= seg_map->text_reloc_tab.len_end)) ||
        ((seg_map->rodata_reloc_tab.end != 0) && (seg_map->rodata_reloc_tab.start >= seg_map->rodata_reloc_tab.end)) ||
        ((seg_map->rodata_reloc_tab.len_end != 0) && (seg_map->rodata_reloc_tab.len_start >= seg_map->rodata_reloc_tab.len_end)) ||
        (seg_map->text_start >= seg_map->text_end) ||
        (seg_map->rodata_start >= seg_map->rodata_end) ||
        (seg_map->data_start >= seg_map->data_end) ||
        (seg_map->bss_start >= seg_map->bss_end)
#endif
            )
    {
        RELOC_DEBUG_PRINTF("assert failed.\n");
        return BAD_FUNC_ARG;
    }

    if (seg_map->start > 0) {
        if ((seg_map->fips_text_start < seg_map->start) ||
            (seg_map->fips_rodata_start < seg_map->start) ||
            (seg_map->verifyCore_start < seg_map->start)
#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)
            ||
            (seg_map->text_reloc_tab.start < seg_map->start) ||
            (seg_map->text_reloc_tab.len_start < seg_map->start) ||
            (seg_map->rodata_reloc_tab.start < seg_map->start) ||
            (seg_map->rodata_reloc_tab.len_start < seg_map->start) ||
            (seg_map->text_start < seg_map->start) ||
            (seg_map->rodata_start < seg_map->start) ||
            (seg_map->data_start < seg_map->start) ||
            (seg_map->bss_start < seg_map->start)
#endif
            )
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BUFFER_E;
        }
    }

    if (seg_map->end > 0) {
        if ((seg_map->fips_text_end > seg_map->end) ||
            (seg_map->fips_rodata_end > seg_map->end) ||
            (seg_map->verifyCore_end > seg_map->end)
#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)
            ||
            ((seg_map->text_reloc_tab.end != 0) &&
             (seg_map->text_reloc_tab.end > seg_map->end)) ||
            ((seg_map->text_reloc_tab.len_end != 0) &&
             (seg_map->text_reloc_tab.len_end > seg_map->end)) ||
            ((seg_map->rodata_reloc_tab.end != 0) &&
             (seg_map->rodata_reloc_tab.end > seg_map->end)) ||
            ((seg_map->rodata_reloc_tab.len_end != 0) &&
             (seg_map->rodata_reloc_tab.len_end > seg_map->end)) ||
            (seg_map->text_end > seg_map->end) ||
            (seg_map->rodata_end > seg_map->end) ||
            (seg_map->data_end > seg_map->end) ||
            (seg_map->bss_end > seg_map->end)
#endif
            )
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BUFFER_E;
        }
    }

#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)
    if ((seg_map->text_reloc_tab.len_end != 0) &&
        (seg_map->text_reloc_tab.len_end - seg_map->text_reloc_tab.len_start != sizeof(word32)))
    {
        RELOC_DEBUG_PRINTF("assert failed.\n");
        return BAD_FUNC_ARG;
    }
    else if (seg_map->text_reloc_tab.len_start & (sizeof(word32) - 1)) {
        /* fprintf(stderr, "%s: seg_map->text_reloc_tab.len_start isn't properly aligned: 0x%llx.\n", progname, (
           unsigned long long)seg_map->text_reloc_tab.len_start); */
        RELOC_DEBUG_PRINTF("assert failed.\n");
        return BAD_ALIGN_E;
    }
    else {
        /* Note we don't currently handle modules that are endian-conflicted
         * with the build host -- that'll be caught here, when reloc_tab_len is
         * a nonsense byte-swapped value, or the final reloc_tab ent has
         * nonsense flags.
         */
        word32 reloc_tab_len = *(const word32 *)seg_map->text_reloc_tab.len_start;
        const struct wc_reloc_table_ent *reloc_tab = (const struct wc_reloc_table_ent *)seg_map->text_reloc_tab.start;
        if (reloc_tab_len == 0) {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        else if ((seg_map->end != 0) &&
            ((unsigned long)(reloc_tab + reloc_tab_len) > seg_map->end))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        else if ((reloc_tab[reloc_tab_len - 1].dest_segment != WC_R_SEG_NONE) ||
                 (reloc_tab[reloc_tab_len - 1].reloc_type != WC_R_NONE))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        else if ((seg_map->text_reloc_tab.end != 0) &&
            (seg_map->text_reloc_tab.end - seg_map->text_reloc_tab.start != sizeof(struct wc_reloc_table_ent) * *(const word32 *)seg_map->text_reloc_tab.len_start))
        {
            /*
              fprintf(stderr, "%s: wc_linuxkm_pie_text_reloc_tab_length from module (%u) is inconsistent with actual text_reloc_tab size %llu.\n",
              progname,
              *(const word32 *)seg_map->text_reloc_tab.len_start,
              (unsigned long long)(seg_map->text_reloc_tab.end - seg_map->text_reloc_tab.start));
            */
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
    }

    if ((seg_map->rodata_reloc_tab.len_end != 0) &&
        (seg_map->rodata_reloc_tab.len_end - seg_map->rodata_reloc_tab.len_start != sizeof(word32)))
    {
        RELOC_DEBUG_PRINTF("assert failed.\n");
        return BAD_FUNC_ARG;
    }
    else if (seg_map->rodata_reloc_tab.len_start & (sizeof(word32) - 1)) {
        /* fprintf(stderr, "%s: seg_map->rodata_reloc_tab.len_start isn't properly aligned: 0x%llx.\n", progname, (
           unsigned long long)seg_map->rodata_reloc_tab.len_start); */
        RELOC_DEBUG_PRINTF("assert failed.\n");
        return BAD_ALIGN_E;
    }
    else {
        /* Note we don't currently handle modules that are endian-conflicted
         * with the build host -- that'll be caught here, when reloc_tab_len is
         * a nonsense byte-swapped value, or the final reloc_tab ent has
         * nonsense flags.
         */
        word32 reloc_tab_len = *(const word32 *)seg_map->rodata_reloc_tab.len_start;
        const struct wc_reloc_table_ent *reloc_tab = (const struct wc_reloc_table_ent *)seg_map->rodata_reloc_tab.start;
        if (reloc_tab_len == 0) {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        else if ((seg_map->end != 0) &&
            ((unsigned long)(reloc_tab + reloc_tab_len) > seg_map->end))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        else if ((reloc_tab[reloc_tab_len - 1].dest_segment != WC_R_SEG_NONE) ||
                 (reloc_tab[reloc_tab_len - 1].reloc_type != WC_R_NONE))
        {
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
        else if ((seg_map->rodata_reloc_tab.end != 0) &&
            (seg_map->rodata_reloc_tab.end - seg_map->rodata_reloc_tab.start != sizeof(struct wc_reloc_table_ent) * *(const word32 *)seg_map->rodata_reloc_tab.len_start))
        {
            /*
              fprintf(stderr, "%s: wc_linuxkm_pie_rodata_reloc_tab_length from module (%u) is inconsistent with actual rodata_reloc_tab size %llu.\n",
              progname,
              *(const word32 *)seg_map->rodata_reloc_tab.len_start,
              (unsigned long long)(seg_map->rodata_reloc_tab.end - seg_map->rodata_reloc_tab.start));
            */
            RELOC_DEBUG_PRINTF("assert failed.\n");
            return BAD_FUNC_ARG;
        }
    }
#endif

    if (out_size == NULL) {
        RELOC_DEBUG_PRINTF("assert failed.\n");
        return BAD_FUNC_ARG;
    }

    if (*out_size < (digest_size * 2) + 1) {
        RELOC_DEBUG_PRINTF("assert failed.\n");
        return BUFFER_E;
    }

    hash = XMALLOC(digest_size, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash == NULL) {
        ret = MEMORY_E;
        RELOC_DEBUG_PRINTF("XMALLOC() failed.\n");
        goto out;
    }

    binCoreKey = XMALLOC(binCoreSz, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (binCoreKey == NULL) {
        ret = MEMORY_E;
        RELOC_DEBUG_PRINTF("XMALLOC() failed.\n");
        goto out;
    }

    {
        word32 base16_out_len = binCoreSz;
        ret = Base16_Decode((const byte *)hmac_key_base16, strlen(hmac_key_base16), binCoreKey, &base16_out_len);
        if (ret != 0) {
            RELOC_DEBUG_PRINTF("Base16_Decode() failed.\n");
            goto out;
        }
        if (base16_out_len != binCoreSz) {
            ret = BAD_FUNC_ARG;
            RELOC_DEBUG_PRINTF("assert failed.\n");
            goto out;
        }
    }

    ret = hmac_setkey(hmac_ctx, binCoreKey, binCoreSz);
    if (ret) {
        RELOC_DEBUG_PRINTF("hmac_setkey() failed.\n");
        goto out;
    }

#if defined(WC_SYM_RELOC_TABLES) || defined(WC_SYM_RELOC_TABLES_SUPPORT)
    {
        ssize_t cur_reloc_index;
        const byte *text_p = (const byte *)seg_map->fips_text_start;
        const byte *rodata_p = (const byte *)seg_map->fips_rodata_start;
        byte *buf = XMALLOC(WOLFSSL_SEGMENT_CANONICALIZER_BUFSIZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        if (! buf) {
            ret = MEMORY_E;
            RELOC_DEBUG_PRINTF("XMALLOC() failed.\n");
            goto out;
        }

        cur_reloc_index = -1;
        while (text_p < (const byte *)seg_map->fips_text_end) {
            size_t text_in_out_len = min(WOLFSSL_SEGMENT_CANONICALIZER_BUFSIZ,
                                         (size_t)((const byte *)seg_map->fips_text_end - text_p));
            ssize_t progress = wc_reloc_normalize_segment(
                text_p,
                &text_in_out_len,
                buf,
                &cur_reloc_index,
                seg_map,
                reloc_counts);
            if (progress <= 0) {
                RELOC_DEBUG_PRINTF("wc_reloc_normalize_segment() for text failed: %zd.\n", progress);
                ret = progress ? (int)progress : IN_CORE_FIPS_E;
                break;
            }
            ret = hmac_update(hmac_ctx, buf, (word32)text_in_out_len);
            if (ret) {
                RELOC_DEBUG_PRINTF("hmac_update() failed.\n");
                break;
            }
            text_p += progress;
        }

        if (ret) {
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            goto out;
        }

        cur_reloc_index = -1;
        while (rodata_p < (const byte *)seg_map->fips_rodata_end) {
            size_t rodata_in_out_len = min(WOLFSSL_SEGMENT_CANONICALIZER_BUFSIZ,
                                           (size_t)((const byte *)seg_map->fips_rodata_end - rodata_p));
            /* don't hash verifyCore or changing verifyCore will change hash */
            if ((rodata_p < (const byte *)seg_map->verifyCore_end) &&
                (rodata_p + rodata_in_out_len >= (const byte *)seg_map->verifyCore_start))
            {
                rodata_in_out_len = (size_t)((const byte *)seg_map->verifyCore_start - rodata_p);
                if (rodata_in_out_len == 0) {
                    rodata_p = (const byte *)seg_map->verifyCore_end;
                    /* force recomputation of relocation offset when skipping
                     * a span (not processed by wc_reloc_normalize_segment()).
                     */
                    cur_reloc_index = -1;
                    continue;
                }
            }

            ssize_t progress = wc_reloc_normalize_segment(
                rodata_p,
                &rodata_in_out_len,
                buf,
                &cur_reloc_index,
                seg_map,
                reloc_counts);
            if (progress <= 0) {
                RELOC_DEBUG_PRINTF("wc_reloc_normalize_segment() for rodata failed: %zd.\n", progress);
                ret = progress ? (int)progress : IN_CORE_FIPS_E;
                break;
            }
            ret = hmac_update(hmac_ctx, buf, (word32)rodata_in_out_len);
            if (ret) {
                RELOC_DEBUG_PRINTF("hmac_update() failed.\n");
                break;
            }
            rodata_p += progress;
        }

        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        if (ret)
            goto out;
    }

#else /* ! (WC_SYM_RELOC_TABLES || WC_SYM_RELOC_TABLES_SUPPORT) */

    (void)reloc_counts;
    WC_SANITIZE_DISABLE();
    ret = hmac_update(hmac_ctx, (byte *)(wc_ptr_t)seg_map->fips_text_start, (word32)(seg_map->fips_text_end - seg_map->fips_text_start));

    if (ret) {
        RELOC_DEBUG_PRINTF("ERROR: hmac_update failed: err %d\n", ret);
        ret = BAD_STATE_E;
        WC_SANITIZE_ENABLE();
        goto out;
    }

    /* don't hash verifyCore or changing verifyCore will change hash */
    if (seg_map->verifyCore_start >= seg_map->fips_rodata_start && seg_map->verifyCore_start < seg_map->fips_rodata_end) {
        ret = hmac_update(hmac_ctx, (byte*)seg_map->fips_rodata_start, (word32)(seg_map->verifyCore_start - (unsigned long)seg_map->fips_rodata_start));
        if (ret) {
            RELOC_DEBUG_PRINTF("ERROR: hmac_update failed: err %d\n", ret);
            ret = BAD_STATE_E;
            goto out;
        }
        ret = hmac_update(hmac_ctx, (const byte *)seg_map->verifyCore_end, (word32)(seg_map->fips_rodata_end - (unsigned long)seg_map->verifyCore_end));
    }
    else {
        ret = hmac_update(hmac_ctx, (byte*)seg_map->fips_rodata_start, (word32)(seg_map->fips_rodata_end - (unsigned long)seg_map->fips_rodata_start));
    }

    WC_SANITIZE_ENABLE();

    if (ret) {
        RELOC_DEBUG_PRINTF("ERROR: hmac_update failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

#endif /* ! (WC_SYM_RELOC_TABLES || WC_SYM_RELOC_TABLES_SUPPORT) */

    ret = hmac_final(hmac_ctx, hash, digest_size);
    if (ret) {
        RELOC_DEBUG_PRINTF("ERROR: hmac_final failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    ret = Base16_Encode(hash, digest_size, (byte *)out, out_size);

  out:

    XFREE(hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(binCoreKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif /* WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE */

#endif /* HAVE_FIPS */
