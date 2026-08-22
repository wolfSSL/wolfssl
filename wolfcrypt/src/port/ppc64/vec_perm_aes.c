/* vec_perm_aes.c — AES-128 using pure AltiVec vec_perm
 *
 * No hardware crypto (vcipher) needed. Runs on G4, G5, POWER7.
 * SubBytes via nibble-indexed vec_perm tables.
 * ShiftRows via single vec_perm.
 * MixColumns via xtime + vec_perm column rotation.
 *
 * Standalone: gcc -maltivec -O2 -DVEC_PERM_AES_BENCHMARK -o vec_perm_aes vec_perm_aes.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* Only compile on PowerPC with AltiVec */
#if defined(__powerpc__) || defined(__ppc__) || defined(__PPC__) || \
    defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || \
    defined(_ARCH_PPC)

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <altivec.h>
#include <string.h>

#ifdef VEC_PERM_AES_BENCHMARK
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#endif

typedef vector unsigned char v16u8;
typedef vector unsigned int  v4u32;
typedef unsigned char u8;

/* ── AES S-box ── */
static const u8 SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const u8 RCON[10] = {1,2,4,8,0x10,0x20,0x40,0x80,0x1b,0x36};

/* 16 vec_perm tables: sbox_vp[h] maps low nibble l -> S[h*16+l] */
static v16u8 sbox_vp[16];

/* ── Constants ── */
/* ShiftRows: column-major AES state permutation */
static const v16u8 SHIFT_ROWS = {0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11};
/* Column rotation by 1 byte within each 4-byte column group */
static const v16u8 COL_ROT1 = {1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12};
/* Column rotation by 2 bytes */
static const v16u8 COL_ROT2 = {2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13};
/* Nibble mask and constants */
static const v16u8 NIBBLE_MASK = {15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15};
static const v16u8 CONST_1B = {0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,
                                0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b,0x1b};
static const v16u8 VEC_ZERO = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const v16u8 VEC_FOUR = {4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4};
static const v16u8 VEC_SEVEN = {7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7};

static void init_sbox_tables(void)
{
    int h, l;
    for (h = 0; h < 16; h++) {
        u8 tbl[16];
        for (l = 0; l < 16; l++)
            tbl[l] = SBOX[h * 16 + l];
        memcpy(&sbox_vp[h], tbl, 16);
    }
}

/* ── SubBytes via vec_perm ──
 * 16 passes: for each high-nibble value, mask matching bytes,
 * look up low nibble in the corresponding S-box table.
 * ~48 vec ops for 16 bytes. Constant-time — no cache side channels.
 */
static inline v16u8 aes_subbytes(v16u8 state)
{
    v16u8 result = VEC_ZERO;
    v16u8 lo = vec_and(state, NIBBLE_MASK);
    v16u8 hi = vec_sr(state, VEC_FOUR);
    int h;

    for (h = 0; h < 16; h++) {
        /* Broadcast h to all 16 byte lanes */
        v16u8 hval;
        if (h <= 15) {
            /* vec_splat_u8 works for 0-15 (5-bit signed immediate) */
            switch(h) {
                case 0:  hval = (v16u8)vec_splat_s8(0);  break;
                case 1:  hval = (v16u8)vec_splat_s8(1);  break;
                case 2:  hval = (v16u8)vec_splat_s8(2);  break;
                case 3:  hval = (v16u8)vec_splat_s8(3);  break;
                case 4:  hval = (v16u8)vec_splat_s8(4);  break;
                case 5:  hval = (v16u8)vec_splat_s8(5);  break;
                case 6:  hval = (v16u8)vec_splat_s8(6);  break;
                case 7:  hval = (v16u8)vec_splat_s8(7);  break;
                case 8:  hval = (v16u8)vec_splat_s8(8);  break;
                case 9:  hval = (v16u8)vec_splat_s8(9);  break;
                case 10: hval = (v16u8)vec_splat_s8(10); break;
                case 11: hval = (v16u8)vec_splat_s8(11); break;
                case 12: hval = (v16u8)vec_splat_s8(12); break;
                case 13: hval = (v16u8)vec_splat_s8(13); break;
                case 14: hval = (v16u8)vec_splat_s8(14); break;
                default: hval = (v16u8)vec_splat_s8(15); break;
            }
        }
        /* Which bytes have this high nibble? */
        vector bool char mask = vec_cmpeq(hi, hval);
        /* Look up low nibble in table for this high nibble */
        v16u8 looked_up = vec_perm(sbox_vp[h], sbox_vp[h], lo);
        /* Merge into result */
        result = vec_sel(result, looked_up, mask);
    }
    return result;
}

/* ── xtime: multiply by 2 in GF(2^8) ── */
static inline v16u8 xtime(v16u8 a)
{
    /* Arithmetic shift right 7: 0x00 if positive, 0xFF if high bit set */
    vector signed char sign = vec_sra((vector signed char)a, (v16u8)VEC_SEVEN);
    v16u8 reduce = vec_and((v16u8)sign, CONST_1B);
    v16u8 shifted = vec_add(a, a); /* a << 1 */
    return vec_xor(shifted, reduce);
}

/* ── MixColumns via vec_perm column rotation + xtime ──
 * Uses the identity: r[i] = s[i] ^ column_sum ^ xtime(s[i] ^ s[(i+1)%4])
 * Only 6 vec ops!
 */
static inline v16u8 mix_columns(v16u8 s)
{
    v16u8 sr1 = vec_perm(s, s, COL_ROT1);       /* s rotated 1 within columns */
    v16u8 pair_xor = vec_xor(s, sr1);            /* s[i] ^ s[(i+1)%4] */
    v16u8 xt = xtime(pair_xor);                  /* xtime of that */
    v16u8 col_sum = vec_xor(pair_xor,
                     vec_perm(pair_xor, pair_xor, COL_ROT2)); /* full column XOR */
    return vec_xor(vec_xor(s, col_sum), xt);
}

/* ── Key Expansion ── */
static void aes128_expand_key(const u8 *key, v16u8 rk[11])
{
    u8 ek[176];
    int i;
    memcpy(ek, key, 16);

    for (i = 16; i < 176; i += 4) {
        u8 t0 = ek[i-4], t1 = ek[i-3], t2 = ek[i-2], t3 = ek[i-1];
        if ((i & 15) == 0) {
            u8 tmp = t0;
            t0 = SBOX[t1] ^ RCON[i/16 - 1];
            t1 = SBOX[t2];
            t2 = SBOX[t3];
            t3 = SBOX[tmp];
        }
        ek[i+0] = ek[i-16] ^ t0;
        ek[i+1] = ek[i-15] ^ t1;
        ek[i+2] = ek[i-14] ^ t2;
        ek[i+3] = ek[i-13] ^ t3;
    }
    for (i = 0; i < 11; i++)
        memcpy(&rk[i], &ek[i*16], 16);
}

/* ── AES-128 ECB Encrypt (single block) ── */
static inline v16u8 aes128_encrypt_block(v16u8 pt, const v16u8 rk[11])
{
    v16u8 s = vec_xor(pt, rk[0]);
    int r;

    for (r = 1; r < 10; r++) {
        s = aes_subbytes(s);
        s = vec_perm(s, s, SHIFT_ROWS);  /* ShiftRows: ONE instruction! */
        s = mix_columns(s);
        s = vec_xor(s, rk[r]);
    }
    /* Last round: no MixColumns */
    s = aes_subbytes(s);
    s = vec_perm(s, s, SHIFT_ROWS);
    s = vec_xor(s, rk[10]);
    return s;
}

/* ── 4-way pipelined ECB (hides AltiVec latency) ── */
static inline void aes128_ecb_4way(v16u8 *b0, v16u8 *b1, v16u8 *b2, v16u8 *b3,
                                    const v16u8 rk[11])
{
    v16u8 s0 = vec_xor(*b0, rk[0]);
    v16u8 s1 = vec_xor(*b1, rk[0]);
    v16u8 s2 = vec_xor(*b2, rk[0]);
    v16u8 s3 = vec_xor(*b3, rk[0]);
    int r;

    for (r = 1; r < 10; r++) {
        s0 = aes_subbytes(s0);
        s1 = aes_subbytes(s1);
        s2 = aes_subbytes(s2);
        s3 = aes_subbytes(s3);
        s0 = vec_perm(s0, s0, SHIFT_ROWS);
        s1 = vec_perm(s1, s1, SHIFT_ROWS);
        s2 = vec_perm(s2, s2, SHIFT_ROWS);
        s3 = vec_perm(s3, s3, SHIFT_ROWS);
        s0 = mix_columns(s0);
        s1 = mix_columns(s1);
        s2 = mix_columns(s2);
        s3 = mix_columns(s3);
        s0 = vec_xor(s0, rk[r]);
        s1 = vec_xor(s1, rk[r]);
        s2 = vec_xor(s2, rk[r]);
        s3 = vec_xor(s3, rk[r]);
    }
    s0 = aes_subbytes(s0); s1 = aes_subbytes(s1);
    s2 = aes_subbytes(s2); s3 = aes_subbytes(s3);
    s0 = vec_perm(s0, s0, SHIFT_ROWS); s1 = vec_perm(s1, s1, SHIFT_ROWS);
    s2 = vec_perm(s2, s2, SHIFT_ROWS); s3 = vec_perm(s3, s3, SHIFT_ROWS);
    *b0 = vec_xor(s0, rk[10]); *b1 = vec_xor(s1, rk[10]);
    *b2 = vec_xor(s2, rk[10]); *b3 = vec_xor(s3, rk[10]);
}

#ifdef VEC_PERM_AES_BENCHMARK
/* ── Helpers ── */
static double now_sec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

static void print_hex(const char *label, const u8 *data, int len)
{
    int i;
    printf("%s", label);
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

/* ── NIST Test Vector ── */
static int verify_nist(const v16u8 rk[11])
{
    /* FIPS-197 Appendix B test vector */
    u8 pt[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                 0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    u8 expected[16] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                       0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
    v16u8 block;
    u8 result[16];

    memcpy(&block, pt, 16);
    block = aes128_encrypt_block(block, rk);
    memcpy(result, &block, 16);

    print_hex("  Plaintext:  ", pt, 16);
    print_hex("  Got:        ", result, 16);
    print_hex("  Expected:   ", expected, 16);

    if (memcmp(result, expected, 16) == 0) {
        printf("  NIST test vector: PASS\n");
        return 1;
    } else {
        printf("  NIST test vector: FAIL\n");
        return 0;
    }
}

/* ── Benchmarks ── */
static void bench_ecb_1way(const v16u8 rk[11])
{
    v16u8 block = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                   0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    long long iters = 0;
    double start = now_sec(), elapsed;
    volatile u8 sink;

    do {
        int i;
        for (i = 0; i < 256; i++)
            block = aes128_encrypt_block(block, rk);
        iters += 256;
        elapsed = now_sec() - start;
    } while (elapsed < 3.0);

    /* Prevent dead code elimination */
    { u8 tmp[16]; memcpy(tmp, &block, 16); sink = tmp[0]; }
    (void)sink;

    printf("  AES-128-ECB (1-way vec_perm): %8.1f MiB/s  (%lld blocks in %.2fs)\n",
           (double)iters * 16.0 / (1024.0 * 1024.0) / elapsed, iters, elapsed);
}

static void bench_ecb_4way(const v16u8 rk[11])
{
    v16u8 b0 = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    v16u8 b1 = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
                0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20};
    v16u8 b2 = {0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
                0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30};
    v16u8 b3 = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
                0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40};
    long long iters = 0;
    double start = now_sec(), elapsed;

    do {
        int i;
        for (i = 0; i < 64; i++)
            aes128_ecb_4way(&b0, &b1, &b2, &b3, rk);
        iters += 256; /* 64 calls * 4 blocks */
        elapsed = now_sec() - start;
    } while (elapsed < 3.0);

    /* Prevent dead code elimination */
    { u8 tmp[16]; memcpy(tmp, &b0, 16); volatile u8 s = tmp[0]; (void)s; }

    printf("  AES-128-ECB (4-way vec_perm): %8.1f MiB/s  (%lld blocks in %.2fs)\n",
           (double)iters * 16.0 / (1024.0 * 1024.0) / elapsed, iters, elapsed);
}

/* ── Scalar reference for comparison ── */
static void bench_scalar(const u8 *key)
{
    u8 rk_bytes[176];
    u8 block[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    long long iters = 0;
    int i, r;
    double start, elapsed;

    /* Expand key */
    memcpy(rk_bytes, key, 16);
    for (i = 16; i < 176; i += 4) {
        u8 t0=rk_bytes[i-4], t1=rk_bytes[i-3], t2=rk_bytes[i-2], t3=rk_bytes[i-1];
        if ((i & 15) == 0) {
            u8 tmp = t0;
            t0 = SBOX[t1] ^ RCON[i/16-1]; t1 = SBOX[t2];
            t2 = SBOX[t3]; t3 = SBOX[tmp];
        }
        rk_bytes[i]=rk_bytes[i-16]^t0; rk_bytes[i+1]=rk_bytes[i-15]^t1;
        rk_bytes[i+2]=rk_bytes[i-14]^t2; rk_bytes[i+3]=rk_bytes[i-13]^t3;
    }

    start = now_sec();
    do {
        for (i = 0; i < 256; i++) {
            /* AddRoundKey */
            for (r = 0; r < 16; r++) block[r] ^= rk_bytes[r];
            /* 9 full rounds */
            for (r = 1; r < 10; r++) {
                u8 tmp[16];
                int j;
                /* SubBytes */
                for (j = 0; j < 16; j++) tmp[j] = SBOX[block[j]];
                /* ShiftRows */
                block[0]=tmp[0]; block[1]=tmp[5]; block[2]=tmp[10]; block[3]=tmp[15];
                block[4]=tmp[4]; block[5]=tmp[9]; block[6]=tmp[14]; block[7]=tmp[3];
                block[8]=tmp[8]; block[9]=tmp[13]; block[10]=tmp[2]; block[11]=tmp[7];
                block[12]=tmp[12]; block[13]=tmp[1]; block[14]=tmp[6]; block[15]=tmp[11];
                /* MixColumns */
                for (j = 0; j < 16; j += 4) {
                    u8 a0=block[j], a1=block[j+1], a2=block[j+2], a3=block[j+3];
                    u8 t = a0^a1^a2^a3;
                    u8 x;
                    x = a0^a1; x = ((x<<1)^((x&0x80)?0x1b:0))^t; block[j] = a0^x;
                    x = a1^a2; x = ((x<<1)^((x&0x80)?0x1b:0))^t; block[j+1] = a1^x;
                    x = a2^a3; x = ((x<<1)^((x&0x80)?0x1b:0))^t; block[j+2] = a2^x;
                    x = a3^a0; x = ((x<<1)^((x&0x80)?0x1b:0))^t; block[j+3] = a3^x;
                }
                /* AddRoundKey */
                for (j = 0; j < 16; j++) block[j] ^= rk_bytes[r*16+j];
            }
            /* Last round */
            {
                u8 tmp[16];
                int j;
                for (j = 0; j < 16; j++) tmp[j] = SBOX[block[j]];
                block[0]=tmp[0]; block[1]=tmp[5]; block[2]=tmp[10]; block[3]=tmp[15];
                block[4]=tmp[4]; block[5]=tmp[9]; block[6]=tmp[14]; block[7]=tmp[3];
                block[8]=tmp[8]; block[9]=tmp[13]; block[10]=tmp[2]; block[11]=tmp[7];
                block[12]=tmp[12]; block[13]=tmp[1]; block[14]=tmp[6]; block[15]=tmp[11];
                for (j = 0; j < 16; j++) block[j] ^= rk_bytes[160+j];
            }
        }
        iters += 256;
        elapsed = now_sec() - start;
    } while (elapsed < 3.0);

    /* Prevent dead code elimination */
    { volatile u8 s = block[0]; (void)s; }

    printf("  AES-128-ECB (scalar ref):     %8.1f MiB/s  (%lld blocks in %.2fs)\n",
           (double)iters * 16.0 / (1024.0 * 1024.0) / elapsed, iters, elapsed);
}

int main(void)
{
    u8 key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                  0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    v16u8 rk[11];

    printf("=== vec_perm AES — Pure AltiVec, No Hardware Crypto ===\n\n");

    init_sbox_tables();
    aes128_expand_key(key, rk);

    printf("[1] NIST FIPS-197 Test Vector:\n");
    if (!verify_nist(rk)) {
        printf("ABORT: correctness check failed!\n");
        return 1;
    }

    printf("\n[2] Benchmark (3 seconds each):\n");
    bench_ecb_1way(rk);
    bench_ecb_4way(rk);
    bench_scalar(key);

    printf("\n[3] Technique:\n");
    printf("  SubBytes:   16x vec_perm (nibble-indexed S-box tables)\n");
    printf("  ShiftRows:  1x vec_perm (byte permutation)\n");
    printf("  MixColumns: xtime via vec_sra + 3x vec_perm column rotation\n");
    printf("  Constant-time: YES (no data-dependent memory access)\n");
    printf("\n  This is the vec_perm path for G4/G5/POWER7.\n");
    printf("  POWER8+ should use vcipher for 10-50x more throughput.\n");

    return 0;
}
#endif /* VEC_PERM_AES_BENCHMARK */

#endif /* __powerpc__ || __ppc__ || __PPC__ || __powerpc64__ || ... */
