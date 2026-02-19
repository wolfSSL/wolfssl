/* linuxkm-fips-hash.c
 *
 * A utility to compute the correct FIPS integrity hash for a fully linked
 * libwolfssl.ko kernel module, and to optionally update the module in place.
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

/* See linuxkm-fips-hash-wrapper.sh for argument setup example. */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <getopt.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/memory.h>

/* failsafe definitions for FIPS <5.3 */
#ifndef FIPS_IN_CORE_DIGEST_SIZE
    #ifndef NO_SHA256
        #define FIPS_IN_CORE_DIGEST_SIZE WC_SHA256_DIGEST_SIZE
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA256
    #elif defined(WOLFSSL_SHA384)
        #define FIPS_IN_CORE_DIGEST_SIZE WC_SHA384_DIGEST_SIZE
        #define FIPS_IN_CORE_HASH_TYPE   WC_SHA384
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

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
extern const char coreKey[FIPS_IN_CORE_KEY_SZ*2 + 1];
#endif

static int hmac_setkey_cb(Hmac *hmac, const byte *key, word32 key_len) {
    int ret;

    ret = wc_HmacSetKey(hmac, FIPS_IN_CORE_HASH_TYPE, key, key_len);
    if (ret != 0)
        return ret;
    return 0;
}

static int hmac_update_cb(Hmac *hmac, const byte *in, word32 in_len) {
    return wc_HmacUpdate_fips(hmac, in, in_len);
}

static int hmac_final_cb(Hmac *hmac, byte *out, word32 out_sz) {
    int actual_size = wc_HmacSizeByType(hmac->macType);
    if (actual_size < 0)
        return actual_size;
    if ((int)out_sz != actual_size)
        return BUFFER_E;
    return wc_HmacFinal(hmac, out);
}

int main(int argc, char **argv)
{
    Hmac hmac;
    int ret;
    struct wc_reloc_table_segments seg_map = WC_RELOC_TABLE_SEGMENTS_INITIALIZER;
    word32 new_verifyCore_size = FIPS_IN_CORE_DIGEST_SIZE*2 + 1;
    char new_verifyCore[new_verifyCore_size];
    const char *progname = strchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
    const char *mod_path = NULL;
    const char *user_coreKey = NULL;
    int mod_fd;
    struct stat st;
    byte *mod_map = MAP_FAILED;
    struct wc_reloc_counts reloc_counts;
    int inplace = 0;
    int quiet = 0;
    int verbose = 0;

    static const struct option long_options[] = {
#define FENCEPOST_OPT_FLAG (1U << 30)
#define FENCEPOST_OPT(x) { .name = #x, .has_arg = required_argument, .flag = NULL, .val = FENCEPOST_OPT_FLAG | offsetof(typeof(seg_map), x) }
        FENCEPOST_OPT(text_start),
        FENCEPOST_OPT(text_end),
        FENCEPOST_OPT(reloc_tab_start),
        FENCEPOST_OPT(reloc_tab_end),
        FENCEPOST_OPT(reloc_tab_len_start),
        FENCEPOST_OPT(reloc_tab_len_end),
        FENCEPOST_OPT(fips_text_start),
        FENCEPOST_OPT(fips_text_end),
        FENCEPOST_OPT(rodata_start),
        FENCEPOST_OPT(rodata_end),
        FENCEPOST_OPT(fips_rodata_start),
        FENCEPOST_OPT(fips_rodata_end),
        FENCEPOST_OPT(verifyCore_start),
        FENCEPOST_OPT(verifyCore_end),
        FENCEPOST_OPT(data_start),
        FENCEPOST_OPT(data_end),
        FENCEPOST_OPT(bss_start),
        FENCEPOST_OPT(bss_end),
        { "core-key", required_argument, NULL, 'k' },
        { "mod-path", required_argument, NULL, 'f' },
        { "in-place", no_argument, NULL, 'i' },
        { "quiet", no_argument, NULL, 'q' },
        { "verbose", no_argument, NULL, 'v' },
        { "help", no_argument, NULL, 'h' },
        { }
    };

    ret = wolfCrypt_Init();
    if (ret < 0) {
        fprintf(stderr, "%s: wolfCrypt_Init() failed: %s.\n", progname, wc_GetErrorString(ret));
        exit(1);
    }

    for (;;) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "f:ik:qvh", long_options, &option_index);
        if (c == -1)
            break;

        if (c & FENCEPOST_OPT_FLAG) {
            char *eptr;
            c &= ~FENCEPOST_OPT_FLAG;
            *((unsigned long *)((byte *)&seg_map + c)) = strtoul(optarg, &eptr, 0);
            if (*eptr != '\0') {
                fprintf(stderr, "%s: %s: supplied arg \"%s\" isn't a valid number.\n", progname, long_options[option_index].name, optarg);
                exit(1);
            }
            continue;
        }

        switch (c) {
        case 'f':
            mod_path = optarg;
            break;
        case 'i':
            inplace = 1;
            break;
        case 'k':
            user_coreKey = optarg;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            printf("usage: %s \\\n", progname);
            for (int i=0; i < (int)(sizeof long_options / sizeof long_options[0]); ++i) {
                const struct option *opt = &long_options[i];
                if (opt->name == NULL) {
                    printf("\n");
                    continue;
                }
                if (i > 0)
                    printf(" \\\n");
                if (opt->has_arg == no_argument)
                    printf("  --%s", opt->name);
                else if (opt->val & FENCEPOST_OPT_FLAG)
                    printf("  --%s <offset>", opt->name);
                else
                    printf("  --%s <arg>", opt->name);
            }
            exit(0);
        case ':':
            fprintf(stderr, "%s: Missing argument.  Try --help.\n", progname);
            exit(1);
            __builtin_unreachable();
        case '?':
            fprintf(stderr, "%s: Unrecognized option.  Try --help.\n", progname);
            exit(1);
            __builtin_unreachable();
        default:
            fprintf(stderr, "%s: Unexpected error.  Try --help.\n", progname);
            exit(1);
            __builtin_unreachable();
        }
    }

    if (optind < argc) {
        fprintf(stderr, "%s: unexpected trailing argument(s).\n", progname);
        exit(1);
    }

    if (user_coreKey == NULL) {
#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
        user_coreKey = coreKey;
#else
        fprintf(stderr, "%s: must supply --core-key.\n", progname);
        exit(1);
#endif
    }

#ifdef WC_USE_PIE_FENCEPOSTS_FOR_FIPS
    if ((seg_map.fips_text_start != ~0UL) ||
        (seg_map.fips_text_end != ~0UL) ||
        (seg_map.fips_rodata_start != ~0UL) ||
        (seg_map.fips_rodata_end != ~0UL))
    {
        fprintf(stderr, "%s: note, ignoring explicit FIPS fenceposts because WC_USE_PIE_FENCEPOSTS_FOR_FIPS.\n", progname);
    }

    seg_map.fips_text_start = seg_map.text_start;
    seg_map.fips_text_end = seg_map.text_end;
    seg_map.fips_rodata_start = seg_map.rodata_start;
    seg_map.fips_rodata_end = seg_map.rodata_end;
#endif

    if ((seg_map.text_start == ~0UL) ||
        (seg_map.text_end == ~0UL) ||
        (seg_map.reloc_tab_start == ~0UL) ||
        (seg_map.reloc_tab_end == ~0UL) ||
        (seg_map.reloc_tab_len_start == ~0UL) ||
        (seg_map.reloc_tab_len_end == ~0UL) ||
        (seg_map.fips_text_start == ~0UL) ||
        (seg_map.fips_text_end == ~0UL) ||
        (seg_map.rodata_start == ~0UL) ||
        (seg_map.rodata_end == ~0UL) ||
        (seg_map.fips_rodata_start == ~0UL) ||
        (seg_map.fips_rodata_end == ~0UL) ||
        (seg_map.verifyCore_start == ~0UL) ||
        (seg_map.verifyCore_end == ~0UL) ||
        (seg_map.data_start == ~0UL) ||
        (seg_map.data_end == ~0UL) ||
        (seg_map.bss_start == ~0UL) ||
        (seg_map.bss_end == ~0UL))
    {
        fprintf(stderr, "%s: segment fencepost(s) missing.  Try --help.\n", progname);
        exit(1);
    }

    if (mod_path == NULL) {
        fprintf(stderr, "%s: module path missing.  Try --help.\n", progname);
        exit(1);
    }

    mod_fd = open(mod_path, inplace ? O_RDWR : O_RDONLY);
    if (mod_fd < 0) {
        fprintf(stderr, "%s: open %s: %m.\n", progname, mod_path);
        exit(1);
    }

    ret = fstat(mod_fd, &st);
    if (ret < 0) {
        fprintf(stderr, "%s: fstat %s: %m.\n", progname, mod_path);
        exit(1);
    }

    if ((seg_map.reloc_tab_start >= seg_map.reloc_tab_end) ||
        (seg_map.reloc_tab_end >= (unsigned long)st.st_size) ||
        (seg_map.reloc_tab_len_start >= seg_map.reloc_tab_len_end) ||
        (seg_map.reloc_tab_len_end >= (unsigned long)st.st_size))
    {
        fprintf(stderr, "%s: supplied reloc_tab fencepost(s) are out of bounds for supplied module %s with length %lu.\n", progname, mod_path, (unsigned long)st.st_size);
        exit(1);
    }

    mod_map = (byte *)mmap(NULL, st.st_size, inplace ? PROT_READ | PROT_WRITE : PROT_READ, MAP_SHARED | MAP_POPULATE, mod_fd, 0);
    if (mod_map == MAP_FAILED) {
        fprintf(stderr, "%s: mmap() of %s, length %zu: %m.\n", progname, mod_path, st.st_size);
        exit(1);
    }

    seg_map.start = (unsigned long)mod_map;
    seg_map.end = (unsigned long)mod_map + st.st_size;

    seg_map.reloc_tab_start += (unsigned long)mod_map;
    seg_map.reloc_tab_end += (unsigned long)mod_map;
    seg_map.reloc_tab_len_start += (unsigned long)mod_map;
    seg_map.reloc_tab_len_end += (unsigned long)mod_map;

    seg_map.verifyCore_start += (unsigned long)mod_map;
    seg_map.verifyCore_end += (unsigned long)mod_map;
    seg_map.fips_text_start += (unsigned long)mod_map;
    seg_map.fips_text_end += (unsigned long)mod_map;
    seg_map.fips_rodata_start += (unsigned long)mod_map;
    seg_map.fips_rodata_end += (unsigned long)mod_map;

    seg_map.text_start += (unsigned long)mod_map;
    seg_map.text_end += (unsigned long)mod_map;
    seg_map.rodata_start += (unsigned long)mod_map;
    seg_map.rodata_end += (unsigned long)mod_map;
    seg_map.data_start += (unsigned long)mod_map;
    seg_map.data_end += (unsigned long)mod_map;
    seg_map.bss_start += (unsigned long)mod_map;
    seg_map.bss_end += (unsigned long)mod_map;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "%s: wc_HmacInit() failed: %s.\n", progname, wc_GetErrorString(ret));
        exit(1);
    }

    if (seg_map.verifyCore_end - seg_map.verifyCore_start != new_verifyCore_size) {
        fprintf(stderr, "%s: unexpected verifyCore length %zu.\n", progname, (size_t)(seg_map.verifyCore_end - seg_map.verifyCore_start));
        ret = -1;
        goto out;
    }

    XMEMSET(&reloc_counts, 0, sizeof(reloc_counts));

    ret = wc_fips_generate_hash(
        &seg_map,
        FIPS_IN_CORE_DIGEST_SIZE,
        user_coreKey,
        &hmac,
        (wc_fips_verifyCore_hmac_setkey_fn)hmac_setkey_cb,
        (wc_fips_verifyCore_hmac_update_fn)hmac_update_cb,
        (wc_fips_verifyCore_hmac_final_fn)hmac_final_cb,
        new_verifyCore,
        &new_verifyCore_size,
        &reloc_counts);

    if (ret < 0) {
        fprintf(stderr, "%s: wc_fips_generate_hash() failed: %s.\n", progname, wc_GetErrorString(ret));
        goto out;
    }

    if (verbose)
        fprintf(inplace ? stdout : stderr, "FIPS-bounded relocation normalizations: text=%d, rodata=%d, rwdata=%d, bss=%d, other=%d\n",
                reloc_counts.text, reloc_counts.rodata, reloc_counts.rwdata, reloc_counts.bss, reloc_counts.other);

    if (new_verifyCore_size < sizeof new_verifyCore) {
        fprintf(stderr, "%s: wc_fips_generate_hash() returned unexpected verifyCore length %u.\n", progname, new_verifyCore_size);
        ret = -1;
        goto out;
    }

    if ((! quiet) && (verbose || !inplace))
        printf("%s\n", new_verifyCore);

    if (strcmp((char *)seg_map.verifyCore_start, new_verifyCore) == 0) {
        fprintf(stderr, "%s: note, verifyCore already matches.\n", progname);
    }
    else if (inplace) {
        XMEMCPY((void *)seg_map.verifyCore_start, new_verifyCore, new_verifyCore_size);
        ret = munmap(mod_map, st.st_size);
        if (ret < 0) {
            fprintf(stderr, "%s: munmap: %m\n", progname);
            exit(1);
        }
        mod_map = MAP_FAILED;
        ret = close(mod_fd);
        if (ret < 0) {
            fprintf(stderr, "%s: close: %m\n", progname);
            exit(1);
        }
        mod_fd = -1;
        printf("FIPS integrity hash updated successfully.\n");
    }

  out:

    wc_HmacFree(&hmac);
    wolfCrypt_Cleanup();

    if (mod_map != MAP_FAILED) {
        if (munmap(mod_map, st.st_size) < 0) {
            fprintf(stderr, "%s: munmap: %m\n", progname);
            if (ret == 0)
                ret = -1;
        }
    }
    if (mod_fd >= 0) {
        if (close(mod_fd) < 0) {
            fprintf(stderr, "%s: close: %m\n", progname);
            if (ret == 0)
                ret = -1;
        }
    }

    if (ret)
        exit(1);
    else
        exit(0);
}
