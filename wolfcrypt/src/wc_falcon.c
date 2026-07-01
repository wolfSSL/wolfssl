/* wc_falcon.c
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

/* Native Falcon implementation for wolfCrypt.
 *
 * Phase 1: verification only (integer arithmetic, no floating point).
 * The signature/keygen paths and the floating-point primitive seam are added
 * in later phases. See wolfssl/wolfcrypt/falcon.h. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha3.h>
#ifndef WOLFSSL_FALCON_VERIFY_ONLY
    #include <wolfssl/wolfcrypt/wc_falcon_keygen.h>
    #include <wolfssl/wolfcrypt/wc_falcon_codec.h>
    #include <wolfssl/wolfcrypt/wc_falcon_sign.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Squared L2-norm acceptance bounds, indexed by logn. Values from the Falcon
 * specification / reference implementation (l2bound table). */
static const word32 falcon_l2bound[] = {
    /* 0..8 unused */ 0, 0, 0, 0, 0, 0, 0, 0, 0,
    34034726u,   /* logn = 9  (Falcon-512)  */
    70265242u    /* logn = 10 (Falcon-1024) */
};

/* ------------------------------------------------------------------------ */
/* Small modular helpers (correctness-first; hot paths are accelerated by the
 * generated per-arch backends in a later phase).                            */
/* ------------------------------------------------------------------------ */

static word32 falcon_modpow(word32 b, word32 e)
{
    word64 r = 1, bb = b % FALCON_Q;
    while (e != 0) {
        if ((e & 1) != 0) {
            r = (r * bb) % FALCON_Q;
        }
        bb = (bb * bb) % FALCON_Q;
        e >>= 1;
    }
    return (word32)r;
}

/* q is prime, so a^(q-2) == a^-1 (mod q). */
static word32 falcon_modinv(word32 a)
{
    return falcon_modpow(a, FALCON_Q - 2);
}

/* Bit-reversed twiddle tables for the degree-n negacyclic verify NTT, keyed by
 * level. psi is a primitive 2n-th root of unity (psi^n == -1 mod q); these were
 * generated once with falcon_modpow/falcon_modinv over the bit-reversal
 * permutation and embedded as read-only constants. Precomputing them avoids
 * both the per-verify O(n) modular-exponentiation cost of rebuilding them and
 * any lazy-initialisation data race on a shared mutable cache. */
static const word16 falcon_zetas_l1[512] = {
        1,  1479,  8246,  5146,  4134,  6553, 11567,  1305,  5860,  3195,  1212, 10643,
     3621,  9744,  8785,  3542,  7311, 10938,  8961,  5777,  5023,  6461,  5728,  4591,
     3006,  9545,   563,  9314,  2625, 11340,  4821,  2639, 12149,  1853,   726,  4611,
    11112,  4255,  2768,  1635,  2963,  7393,  2366,  9238,  9198, 12208, 11289,  7969,
     8736,  4805, 11227,  2294,  9542,  4846,  9154,  8577,  9275,  3201,  7203, 10963,
     1170,  9970,   955, 11499,  8340,  8993,  2396,  4452,  6915,  2837,   130,  7935,
    11336,  3748,  6522, 11462,  5067, 10092, 12171,  9813,  8011,  1673,  5331,  7300,
    10908,  9764,  4177,  8705,   480,  9447,  1022, 12280,  5791, 11745,  9821, 11950,
    12144,  6747,  8652,  3459,  2731,  8357,  6378,  7399, 10530,  3707,  8595,  5179,
     3382,   355,  4231,  2548,  9048, 11560,  3289, 10276,  9005,  9408,  5092, 10200,
     6534,  4632,  4388,  1260,   334,  2426,  1428, 10593,  3400,  2399,  5191,  9153,
     9273,   243,  3000,   671,  3531, 11813,  3985,  7384, 10111, 10745,  6730, 11869,
     9042,  2686,  2969,  3978,  8779,  6957,  9424,  2370,  8241, 10040,  9405, 11136,
     3186,  5407, 10163,  1630,  3271,  8232, 10600,  8925,  4414,  2847, 10115,  4372,
     9509,  5195,  7394, 10805,  9984,  7247,  4053,  9644, 12176,  4919,  2166,  8374,
    12129,  9140,  7852,     3,  1426,  7635, 10512,  1663,  8653,  4938,  2704,  5291,
     5277,  1168, 11082,  9041,  2143, 11224, 11885,  4645,  4096, 11796,  5444,  2381,
    10911,  1912,  4337, 11854,  4976, 10682, 11414,  8509, 11287,  5011,  8005,  5088,
     9852,  8643,  9302,  6267,  2422,  6039,  2187,  2566, 10849,  8526,  9223,    27,
     7205,  1632,  7404,  1017,  4143,  7575, 12047, 10752,  8585,  2678,  7270, 11744,
     3833,  3778, 11899,   773,  5101, 11222,  9888,   442,  9377,  6591,   354,  7428,
     5012,  2481,  1045,  9430, 10302, 10587,  8724, 11635,  7083,  5529,  9090, 12233,
     6152,  4948,   400,  1728,  6427,  6136,  6874,  3643, 10930,  5435,  1254, 11316,
    10256,  3998, 10367,  8410, 11821,  8301, 11907,   316,  6950,  5446,  6093,  3710,
     7822,  4789,  7540,  5537,  3789,   147,  5456,  7840, 11239,  7753,  5445,  3860,
     9606,  1190,  8471,  6118,  5925,  1018,  8775,  1041,  1973,  5574, 11011,  2344,
     4075,  5315,  4324,  4916, 10120, 11767,  7210,  9027,  6281, 11404,  7280,  1956,
    11286,  3532, 12048, 12231,  1105, 12147,  5681,  8812,  8851,  2844,   975,  4212,
     8687,  6068,   421,  8209,  3600,  3263,  7665,  6077,  4782,  6403,  9260,  5594,
     8076, 11785,   605,  9987,  5468,  1010,   787,  8807,  5241,  9369,  9162,  8120,
     5057,  7591,  3445,  7509,  2049,  7377, 10968,   192,   431, 10710,  2505,  5906,
    12138, 10162,  8332,  9450,  6415,   677,  6234,  3336, 12237,  9115,  1323,  2766,
     3150,  1319,  8243,   709,  8049,  8719, 11454,  6224,   922, 11848,  8210,  1058,
     1958,  7967, 10211, 11177,    64,  8633, 11606,  9830,  6507,  1566,  2948,  9786,
     6370,  7856,  3834,  5257, 10542,  9166,  9235,  5486,  1404, 11964,  1146, 11341,
     3728,  8240,  6299,  1159,  6099,   295,  5766, 11637,  8527,  2919,  8273,  8212,
     3329,  7991,  9597,   168, 10695,  1962,  5106,  6328,  5297,  6170,  3956,  1360,
    11089,  7105,  9734,  6167,  9407,  1805,  1954,  2051,  6142,  2447,  3963, 11713,
     8855,  8760,  9381,   218,  9928, 10446,  9259,  4115,  5333, 10258,  5876,  2281,
      156,  9522,  8320,  3991,   453,  6381, 11871,  8517,  4774,  6860,  4737,  1293,
    10232,  5369,  9087,  7796,   350,  1512, 10474,  6906,  1489,  2500,  1583,  6347,
    11026, 12240,  6374,  1483,  3009,  1693,   723,   174,  2738,  6421,  2655,  6554,
    10314,  3757,  9364, 11942,  7535, 10431,   426,  3315,
};
static const word16 falcon_izetas_l1[512] = {
        1, 10810,  7143,  4043, 10984,   722,  5736,  8155,  8747,  3504,  2545,  8668,
     1646, 11077,  9094,  6429,  9650,  7468,   949,  9664,  2975, 11726,  2744,  9283,
     7698,  6561,  5828,  7266,  6512,  3328,  1351,  4978,   790, 11334,  2319, 11119,
     1326,  5086,  9088,  3014,  3712,  3135,  7443,  2747,  9995,  1062,  7484,  3553,
     4320,  1000,    81,  3091,  3051,  9923,  4896,  9326, 10654,  9521,  8034,  1177,
     7678, 11563, 10436,   140,  1696, 10861,  9863, 11955, 11029,  7901,  7657,  5755,
     2089,  7197,  2881,  3284,  2013,  9000,   729,  3241,  9741,  8058, 11934,  8907,
     7110,  3694,  8582,  1759,  4890,  5911,  3932,  9558,  8830,  3637,  5542,   145,
      339,  2468,   544,  6498,     9, 11267,  2842, 11809,  3584,  8112,  2525,  1381,
     4989,  6958, 10616,  4278,  2476,   118,  2197,  7222,   827,  5767,  8541,   953,
     4354, 12159,  9452,  5374,  7837,  9893,  3296,  3949,  2859, 11244,  9808,  7277,
     4861, 11935,  5698,  2912, 11847,  2401,  1067,  7188, 11516,   390,  8511,  8456,
      545,  5019,  9611,  3704,  1537,   242,  4714,  8146, 11272,  4885, 10657,  5084,
    12262,  3066,  3763,  1440,  9723, 10102,  6250,  9867,  6022,  2987,  3646,  2437,
     7201,  4284,  7278,  1002,  3780,   875,  1607,  7313,   435,  7952, 10377,  1378,
     9908,  6845,   493,  8193,  7644,   404,  1065, 10146,  3248,  1207, 11121,  7012,
     6998,  9585,  7351,  3636, 10626,  1777,  4654, 10863, 12286,  4437,  3149,   160,
     3915, 10123,  7370,   113,  2645,  8236,  5042,  2305,  1484,  4895,  7094,  2780,
     7917,  2174,  9442,  7875,  3364,  1689,  4057,  9018, 10659,  2126,  6882,  9103,
     1153,  2884,  2249,  4048,  9919,  2865,  5332,  3510,  8311,  9320,  9603,  3247,
      420,  5559,  1544,  2178,  4905,  8304,   476,  8758, 11618,  9289, 12046,  3016,
     3136,  7098,  9890,  8889,  8974, 11863,  1858,  4754,   347,  2925,  8532,  1975,
     5735,  9634,  5868,  9551, 12115, 11566, 10596,  9280, 10806,  5915,    49,  1263,
     5942, 10706,  9789, 10800,  5383,  1815, 10777, 11939,  4493,  3202,  6920,  2057,
    10996,  7552,  5429,  7515,  3772,   418,  5908, 11836,  8298,  3969,  2767, 12133,
    10008,  6413,  2031,  6956,  8174,  3030,  1843,  2361, 12071,  2908,  3529,  3434,
      576,  8326,  9842,  6147, 10238, 10335, 10484,  2882,  6122,  2555,  5184,  1200,
    10929,  8333,  6119,  6992,  5961,  7183, 10327,  1594, 12121,  2692,  4298,  8960,
     4077,  4016,  9370,  3762,   652,  6523, 11994,  6190, 11130,  5990,  4049,  8561,
      948, 11143,   325, 10885,  6803,  3054,  3123,  1747,  7032,  8455,  4433,  5919,
     2503,  9341, 10723,  5782,  2459,   683,  3656, 12225,  1112,  2078,  4322, 10331,
    11231,  4079,   441, 11367,  6065,   835,  3570,  4240, 11580,  4046, 10970,  9139,
     9523, 10966,  3174,    52,  8953,  6055, 11612,  5874,  2839,  3957,  2127,   151,
     6383,  9784,  1579, 11858, 12097,  1321,  4912, 10240,  4780,  8844,  4698,  7232,
     4169,  3127,  2920,  7048,  3482, 11502, 11279,  6821,  2302, 11684,   504,  4213,
     6695,  3029,  5886,  7507,  6212,  4624,  9026,  8689,  4080, 11868,  6221,  3602,
     8077, 11314,  9445,  3438,  3477,  6608,   142, 11184,    58,   241,  8757,  1003,
    10333,  5009,   885,  6008,  3262,  5079,   522,  2169,  7373,  7965,  6974,  8214,
     9945,  1278,  6715, 10316, 11248,  3514, 11271,  6364,  6171,  3818, 11099,  2683,
     8429,  6844,  4536,  1050,  4449,  6833, 12142,  8500,  6752,  4749,  7500,  4467,
     8579,  6196,  6843,  5339, 11973,   382,  3988,   468,  3879,  1922,  8291,  2033,
      973, 11035,  6854,  1359,  8646,  5415,  6153,  5862, 10561, 11889,  7341,  6137,
       56,  3199,  6760,  5206,   654,  3565,  1702,  1987,
};
static const word16 falcon_zetas_l5[1024] = {
        1,  1479,  8246,  5146,  4134,  6553, 11567,  1305,  5860,  3195,  1212, 10643,
     3621,  9744,  8785,  3542,  7311, 10938,  8961,  5777,  5023,  6461,  5728,  4591,
     3006,  9545,   563,  9314,  2625, 11340,  4821,  2639, 12149,  1853,   726,  4611,
    11112,  4255,  2768,  1635,  2963,  7393,  2366,  9238,  9198, 12208, 11289,  7969,
     8736,  4805, 11227,  2294,  9542,  4846,  9154,  8577,  9275,  3201,  7203, 10963,
     1170,  9970,   955, 11499,  8340,  8993,  2396,  4452,  6915,  2837,   130,  7935,
    11336,  3748,  6522, 11462,  5067, 10092, 12171,  9813,  8011,  1673,  5331,  7300,
    10908,  9764,  4177,  8705,   480,  9447,  1022, 12280,  5791, 11745,  9821, 11950,
    12144,  6747,  8652,  3459,  2731,  8357,  6378,  7399, 10530,  3707,  8595,  5179,
     3382,   355,  4231,  2548,  9048, 11560,  3289, 10276,  9005,  9408,  5092, 10200,
     6534,  4632,  4388,  1260,   334,  2426,  1428, 10593,  3400,  2399,  5191,  9153,
     9273,   243,  3000,   671,  3531, 11813,  3985,  7384, 10111, 10745,  6730, 11869,
     9042,  2686,  2969,  3978,  8779,  6957,  9424,  2370,  8241, 10040,  9405, 11136,
     3186,  5407, 10163,  1630,  3271,  8232, 10600,  8925,  4414,  2847, 10115,  4372,
     9509,  5195,  7394, 10805,  9984,  7247,  4053,  9644, 12176,  4919,  2166,  8374,
    12129,  9140,  7852,     3,  1426,  7635, 10512,  1663,  8653,  4938,  2704,  5291,
     5277,  1168, 11082,  9041,  2143, 11224, 11885,  4645,  4096, 11796,  5444,  2381,
    10911,  1912,  4337, 11854,  4976, 10682, 11414,  8509, 11287,  5011,  8005,  5088,
     9852,  8643,  9302,  6267,  2422,  6039,  2187,  2566, 10849,  8526,  9223,    27,
     7205,  1632,  7404,  1017,  4143,  7575, 12047, 10752,  8585,  2678,  7270, 11744,
     3833,  3778, 11899,   773,  5101, 11222,  9888,   442,  9377,  6591,   354,  7428,
     5012,  2481,  1045,  9430, 10302, 10587,  8724, 11635,  7083,  5529,  9090, 12233,
     6152,  4948,   400,  1728,  6427,  6136,  6874,  3643, 10930,  5435,  1254, 11316,
    10256,  3998, 10367,  8410, 11821,  8301, 11907,   316,  6950,  5446,  6093,  3710,
     7822,  4789,  7540,  5537,  3789,   147,  5456,  7840, 11239,  7753,  5445,  3860,
     9606,  1190,  8471,  6118,  5925,  1018,  8775,  1041,  1973,  5574, 11011,  2344,
     4075,  5315,  4324,  4916, 10120, 11767,  7210,  9027,  6281, 11404,  7280,  1956,
    11286,  3532, 12048, 12231,  1105, 12147,  5681,  8812,  8851,  2844,   975,  4212,
     8687,  6068,   421,  8209,  3600,  3263,  7665,  6077,  4782,  6403,  9260,  5594,
     8076, 11785,   605,  9987,  5468,  1010,   787,  8807,  5241,  9369,  9162,  8120,
     5057,  7591,  3445,  7509,  2049,  7377, 10968,   192,   431, 10710,  2505,  5906,
    12138, 10162,  8332,  9450,  6415,   677,  6234,  3336, 12237,  9115,  1323,  2766,
     3150,  1319,  8243,   709,  8049,  8719, 11454,  6224,   922, 11848,  8210,  1058,
     1958,  7967, 10211, 11177,    64,  8633, 11606,  9830,  6507,  1566,  2948,  9786,
     6370,  7856,  3834,  5257, 10542,  9166,  9235,  5486,  1404, 11964,  1146, 11341,
     3728,  8240,  6299,  1159,  6099,   295,  5766, 11637,  8527,  2919,  8273,  8212,
     3329,  7991,  9597,   168, 10695,  1962,  5106,  6328,  5297,  6170,  3956,  1360,
    11089,  7105,  9734,  6167,  9407,  1805,  1954,  2051,  6142,  2447,  3963, 11713,
     8855,  8760,  9381,   218,  9928, 10446,  9259,  4115,  5333, 10258,  5876,  2281,
      156,  9522,  8320,  3991,   453,  6381, 11871,  8517,  4774,  6860,  4737,  1293,
    10232,  5369,  9087,  7796,   350,  1512, 10474,  6906,  1489,  2500,  1583,  6347,
    11026, 12240,  6374,  1483,  3009,  1693,   723,   174,  2738,  6421,  2655,  6554,
    10314,  3757,  9364, 11942,  7535, 10431,   426,  3315,  1945,  1029,  1325,  5724,
     3624,  1892,  8945,  6691,  5797,  8330, 10141,  5959,  1248,  2442,  5115,  7350,
     1522,  2151,  3343,  4119, 12269,  7287,  7126,  7681,  9395,  8635,  1314,  1744,
     5690,  9834,   338,  8342, 10347,  3408, 11124,  9714,  8778,  5478,  1178,  9513,
    11783,  1255,  5784,  1392,  9615,  2212,  8951,  3276,  8122,  6085, 11251,   923,
     2800, 12096, 10058,  6092, 11912,  7711,   375,  1620,  2185, 11897,  1836, 11864,
    12109,  4138,  2689,  7684,  5509,   204,  7070, 10880,  2054,  2483,  3042,  1344,
    11826,  3407,  3981,  1468, 11232,  9689,  9168,  4705,  5246,  4475,  1236,  9272,
    11925,  2360,  9261,  7073,  6771, 11063,  4739,  4251,   622, 10552,  4499,  5672,
     2947,  8307,  5609,   636,  7376,  8761,  4235,  8464,  3375,  2291,  7954,  3393,
      512,  7619,  6825,  4906,  2900,   239, 11295,  4554,  1804,  1403,  6094,  5189,
    10602, 11883,   146,  7021,  1518,  8524,  7226,  8113,  8022,  5653, 10014,  2461,
    10533,  8144,  8755,  8328,  3495,  7725,  2065,  6463,  1131,  1445, 11164,  7429,
     5734,  1176,  6781,  1275,  3889,   579,  6693,  6302,  3114,  9520,  6323, 12077,
     8682, 10962,  8347,  7057,  7508,  7365, 11275, 11841,    60,  2717,  3200,  1535,
     2260, 12221,  5836,  4566,  1417,  6613, 10032,  4505,  8314,  7406,  9202,  5835,
     8545,  4963,  9233,  2528,  6444,  6701, 11877,  5102,  2450, 10584, 11873, 11475,
     2164,  5416,   716,  2110,  3448, 11946,  7751, 10381, 11081,  7562,  5211,  1866,
     6877,  8080,  6296,  9011,  5061,  1218, 11851,  3515,  3589, 11572,  2982, 10916,
     4103,  9860,  1721,  1536,  1092,  5209,  9084,  3359,  4265,  3678, 10361, 11825,
     8840, 11153,  8581,  9051,  9363, 10463,  7800,  9118,  8051, 11677,  3368,  4227,
     4222,  1526, 12164, 11749,  1389,  2068,   346,  7885,  3163,  8257,  4840,  6162,
     6320,  7640,  9360,  6026,   466,  1030,  8468,  1681,  8443,  1573,  3793,  6063,
     2602,  1901, 11787,  7171, 11169,  2535,  5808,    21,  2873,  9462,  9855,   791,
    11415,  9988,  6639,   170, 12139, 11641,  4289,  2307,     8, 11832,  4523,  4301,
     8494,  3268,  6513, 10440, 10013,   982,  9696, 11410,  4390,  4218,  8835,  3758,
     9332,  1481, 10243,  9349,  3317,  2532,  8957, 12150, 11759,  2626,  4504,   778,
     8711,  4697,  1701,  8823,  1279, 11424,  2672,  7119,  3116,   189, 10526, 10080,
    10939,  6457,  1734,  8474, 10595,  1530,  3869,  7866, 11129,  4820,  7771,  3094,
     9559,  5411,  1868, 10036, 10506,  5078,  7315,  4565,  2478,  2840,  9270,  8095,
     5275, 10499,  6879, 11038,  6164, 10407,  1040,  2035,  4665,  5406,  3020,  5673,
     3669,  7002, 11345,  4770,  2643,  1095,  5781,  9244,  1241,  4378,  8838,  8195,
     3840,  1842,  8176, 12217,  9461,  7937,  4834,  9577,  6828,  9343,  7779,  2637,
    11408, 11924, 10362,  1015, 11385,  2485,  5039,  5547, 11009, 11675,  1371,    24,
     1590,  4411, 11066,  9955, 10734, 10487,  7186, 10398,  2338,  4693,  9996,   417,
     6138,  8820,  7846,  3418,  2622,  6903,  4661, 11779,   450,  1944, 11711,  5368,
     3670,  8481,  7302,  9916,  7154, 12226,  4684,  8929, 10891,  9199, 11463,  7246,
     8787,  6500,  1658,  6671,  4483,  6586,  1506,  3065,   910,  6389,  7570,   751,
    10583,  8360,  3229,  7559,  1282,  3572,  2832, 10268,  6086,  5646,  9169,  6184,
     3941,  3753,  5370,  3536,   769,  6763,    50,   216,  8484,   767, 10076,  8136,
     8566, 11444, 10353, 12282,  7235,  9135,  9004,  7929,  5349,  9344,  2633, 10883,
     4855,  3769,  9057,   293,  8190,  8345,  6685,  6759,  1265,  3007, 10118,  8809,
     2941, 11722,  5289,  6627,  4273,  3221,  2595,  3837,  5082,  7699,   682,   980,
     7087, 11445,  5207,  8239,
};
static const word16 falcon_izetas_l5[1024] = {
        1, 10810,  7143,  4043, 10984,   722,  5736,  8155,  8747,  3504,  2545,  8668,
     1646, 11077,  9094,  6429,  9650,  7468,   949,  9664,  2975, 11726,  2744,  9283,
     7698,  6561,  5828,  7266,  6512,  3328,  1351,  4978,   790, 11334,  2319, 11119,
     1326,  5086,  9088,  3014,  3712,  3135,  7443,  2747,  9995,  1062,  7484,  3553,
     4320,  1000,    81,  3091,  3051,  9923,  4896,  9326, 10654,  9521,  8034,  1177,
     7678, 11563, 10436,   140,  1696, 10861,  9863, 11955, 11029,  7901,  7657,  5755,
     2089,  7197,  2881,  3284,  2013,  9000,   729,  3241,  9741,  8058, 11934,  8907,
     7110,  3694,  8582,  1759,  4890,  5911,  3932,  9558,  8830,  3637,  5542,   145,
      339,  2468,   544,  6498,     9, 11267,  2842, 11809,  3584,  8112,  2525,  1381,
     4989,  6958, 10616,  4278,  2476,   118,  2197,  7222,   827,  5767,  8541,   953,
     4354, 12159,  9452,  5374,  7837,  9893,  3296,  3949,  2859, 11244,  9808,  7277,
     4861, 11935,  5698,  2912, 11847,  2401,  1067,  7188, 11516,   390,  8511,  8456,
      545,  5019,  9611,  3704,  1537,   242,  4714,  8146, 11272,  4885, 10657,  5084,
    12262,  3066,  3763,  1440,  9723, 10102,  6250,  9867,  6022,  2987,  3646,  2437,
     7201,  4284,  7278,  1002,  3780,   875,  1607,  7313,   435,  7952, 10377,  1378,
     9908,  6845,   493,  8193,  7644,   404,  1065, 10146,  3248,  1207, 11121,  7012,
     6998,  9585,  7351,  3636, 10626,  1777,  4654, 10863, 12286,  4437,  3149,   160,
     3915, 10123,  7370,   113,  2645,  8236,  5042,  2305,  1484,  4895,  7094,  2780,
     7917,  2174,  9442,  7875,  3364,  1689,  4057,  9018, 10659,  2126,  6882,  9103,
     1153,  2884,  2249,  4048,  9919,  2865,  5332,  3510,  8311,  9320,  9603,  3247,
      420,  5559,  1544,  2178,  4905,  8304,   476,  8758, 11618,  9289, 12046,  3016,
     3136,  7098,  9890,  8889,  8974, 11863,  1858,  4754,   347,  2925,  8532,  1975,
     5735,  9634,  5868,  9551, 12115, 11566, 10596,  9280, 10806,  5915,    49,  1263,
     5942, 10706,  9789, 10800,  5383,  1815, 10777, 11939,  4493,  3202,  6920,  2057,
    10996,  7552,  5429,  7515,  3772,   418,  5908, 11836,  8298,  3969,  2767, 12133,
    10008,  6413,  2031,  6956,  8174,  3030,  1843,  2361, 12071,  2908,  3529,  3434,
      576,  8326,  9842,  6147, 10238, 10335, 10484,  2882,  6122,  2555,  5184,  1200,
    10929,  8333,  6119,  6992,  5961,  7183, 10327,  1594, 12121,  2692,  4298,  8960,
     4077,  4016,  9370,  3762,   652,  6523, 11994,  6190, 11130,  5990,  4049,  8561,
      948, 11143,   325, 10885,  6803,  3054,  3123,  1747,  7032,  8455,  4433,  5919,
     2503,  9341, 10723,  5782,  2459,   683,  3656, 12225,  1112,  2078,  4322, 10331,
    11231,  4079,   441, 11367,  6065,   835,  3570,  4240, 11580,  4046, 10970,  9139,
     9523, 10966,  3174,    52,  8953,  6055, 11612,  5874,  2839,  3957,  2127,   151,
     6383,  9784,  1579, 11858, 12097,  1321,  4912, 10240,  4780,  8844,  4698,  7232,
     4169,  3127,  2920,  7048,  3482, 11502, 11279,  6821,  2302, 11684,   504,  4213,
     6695,  3029,  5886,  7507,  6212,  4624,  9026,  8689,  4080, 11868,  6221,  3602,
     8077, 11314,  9445,  3438,  3477,  6608,   142, 11184,    58,   241,  8757,  1003,
    10333,  5009,   885,  6008,  3262,  5079,   522,  2169,  7373,  7965,  6974,  8214,
     9945,  1278,  6715, 10316, 11248,  3514, 11271,  6364,  6171,  3818, 11099,  2683,
     8429,  6844,  4536,  1050,  4449,  6833, 12142,  8500,  6752,  4749,  7500,  4467,
     8579,  6196,  6843,  5339, 11973,   382,  3988,   468,  3879,  1922,  8291,  2033,
      973, 11035,  6854,  1359,  8646,  5415,  6153,  5862, 10561, 11889,  7341,  6137,
       56,  3199,  6760,  5206,   654,  3565,  1702,  1987,  4050,  7082,   844,  5202,
    11309, 11607,  4590,  7207,  8452,  9694,  9068,  8016,  5662,  7000,   567,  9348,
     3480,  2171,  9282, 11024,  5530,  5604,  3944,  4099, 11996,  3232,  8520,  7434,
     1406,  9656,  2945,  6940,  4360,  3285,  3154,  5054,     7,  1936,   845,  3723,
     4153,  2213, 11522,  3805, 12073, 12239,  5526, 11520,  8753,  6919,  8536,  8348,
     6105,  3120,  6643,  6203,  2021,  9457,  8717, 11007,  4730,  9060,  3929,  1706,
    11538,  4719,  5900, 11379,  9224, 10783,  5703,  7806,  5618, 10631,  5789,  3502,
     5043,   826,  3090,  1398,  3360,  7605,    63,  5135,  2373,  4987,  3808,  8619,
     6921,   578, 10345, 11839,   510,  7628,  5386,  9667,  8871,  4443,  3469,  6151,
    11872,  2293,  7596,  9951,  1891,  5103,  1802,  1555,  2334,  1223,  7878, 10699,
    12265, 10918,   614,  1280,  6742,  7250,  9804,   904, 11274,  1927,   365,   881,
     9652,  4510,  2946,  5461,  2712,  7455,  4352,  2828,    72,  4113, 10447,  8449,
     4094,  3451,  7911, 11048,  3045,  6508, 11194,  9646,  7519,   944,  5287,  8620,
     6616,  9269,  6883,  7624, 10254, 11249,  1882,  6125,  1251,  5410,  1790,  7014,
     4194,  3019,  9449,  9811,  7724,  4974,  7211,  1783,  2253, 10421,  6878,  2730,
     9195,  4518,  7469,  1160,  4423,  8420, 10759,  1694,  3815, 10555,  5832,  1350,
     2209,  1763, 12100,  9173,  5170,  9617,   865, 11010,  3466, 10588,  7592,  3578,
    11511,  7785,  9663,   530,   139,  3332,  9757,  8972,  2940,  2046, 10808,  2957,
     8531,  3454,  8071,  7899,   879,  2593, 11307,  2276,  1849,  5776,  9021,  3795,
     7988,  7766,   457, 12281,  9982,  8000,   648,   150, 12119,  5650,  2301,   874,
    11498,  2434,  2827,  9416, 12268,  6481,  9754,  1120,  5118,   502, 10388,  9687,
     6226,  8496, 10716,  3846, 10608,  3821, 11259, 11823,  6263,  2929,  4649,  5969,
     6127,  7449,  4032,  9126,  4404, 11943, 10221, 10900,   540,   125, 10763,  8067,
     8062,  8921,   612,  4238,  3171,  4489,  1826,  2926,  3238,  3708,  1136,  3449,
      464,  1928,  8611,  8024,  8930,  3205,  7080, 11197, 10753, 10568,  2429,  8186,
     1373,  9307,   717,  8700,  8774,   438, 11071,  7228,  3278,  5993,  4209,  5412,
    10423,  7078,  4727,  1208,  1908,  4538,   343,  8841, 10179, 11573,  6873, 10125,
      814,   416,  1705,  9839,  7187,   412,  5588,  5845,  9761,  3056,  7326,  3744,
     6454,  3087,  4883,  3975,  7784,  2257,  5676, 10872,  7723,  6453,    68, 10029,
    10754,  9089,  9572, 12229,   448,  1014,  4924,  4781,  5232,  3942,  1327,  3607,
      212,  5966,  2769,  9175,  5987,  5596, 11710,  8400, 11014,  5508, 11113,  6555,
     4860,  1125, 10844, 11158,  5826, 10224,  4564,  8794,  3961,  3534,  4145,  1756,
     9828,  2275,  6636,  4267,  4176,  5063,  3765, 10771,  5268, 12143,   406,  1687,
     7100,  6195, 10886, 10485,  7735,   994, 12050,  9389,  7383,  5464,  4670, 11777,
     8896,  4335,  9998,  8914,  3825,  8054,  3528,  4913, 11653,  6680,  3982,  9342,
     6617,  7790,  1737, 11667,  8038,  7550,  1226,  5518,  5216,  3028,  9929,   364,
     3017, 11053,  7814,  7043,  7584,  3121,  2600,  1057, 10821,  8308,  8882,   463,
    10945,  9247,  9806, 10235,  1409,  5219, 12085,  6780,  4605,  9600,  8151,   180,
      425, 10453,   392, 10104, 10669, 11914,  4578,   377,  6197,  2231,   193,  9489,
    11366,  1038,  6204,  4167,  9013,  3338, 10077,  2674, 10897,  6505, 11034,   506,
     2776, 11111,  6811,  3511,  2575,  1165,  8881,  1942,  3947, 11951,  2455,  6599,
    10545, 10975,  3654,  2894,  4608,  5163,  5002,    20,  8170,  8946, 10138, 10767,
     4939,  7174,  9847, 11041,  6330,  2148,  3959,  6492,  5598,  3344, 10397,  8665,
     6565, 10964, 11260, 10344,
};

static void falcon_get_tables(unsigned logn, const word16** zetas,
        const word16** izetas)
{
    if (logn == FALCON_LEVEL1_LOGN) {
        *zetas  = falcon_zetas_l1;
        *izetas = falcon_izetas_l1;
    }
    else {
        *zetas  = falcon_zetas_l5;
        *izetas = falcon_izetas_l5;
    }
}

/* Division-free modular reductions for the NTT. Hardware integer division is
 * absent on Cortex-M0/M3 (a slow library call) and multi-cycle elsewhere, so
 * the inner loops use a Barrett multiply + a conditional subtract instead of
 * '%'. Both are bit-identical to a mod q and constant-time.
 *   falcon_barrett: a in [0, q^2) -> [0, q)  (349496 = floor(2^32 / q)).
 *   falcon_csub:    a in [0, 2q)  -> [0, q). */
static WC_INLINE word32 falcon_barrett(word32 a)
{
    word32 t = (word32)(((word64)a * 349496u) >> 32);
    a -= t * FALCON_Q;
    a -= FALCON_Q & (word32)((sword32)(FALCON_Q - 1 - a) >> 31);
    return a;
}
static WC_INLINE word32 falcon_csub(word32 a)
{
    a -= FALCON_Q & (word32)((sword32)(FALCON_Q - 1 - a) >> 31);
    return a;
}

/* Optional ARM DSP acceleration for the verify path (NTT/iNTT/pointwise/norm).
 * On cores with the DSP extension (__ARM_FEATURE_DSP: Cortex-M4/M7/M33, ...) the
 * butterflies process two packed 16-bit coefficients per iteration using the
 * SMLA* 16x16 multiplies, SADD16/SSUB16 packed adds, and a USUB16+SEL packed
 * conditional subtract; the squared-norm accumulates two lanes per SMUAD. Every
 * result is bit-identical to the scalar Barrett path below. Define
 * WOLFSSL_FALCON_NO_NTT_DSP to force the portable C path. */
#if !defined(WOLFSSL_FALCON_NTT_DSP) && defined(__ARM_FEATURE_DSP) && \
    !defined(WOLFSSL_FALCON_NO_NTT_DSP)
    #define WOLFSSL_FALCON_NTT_DSP
#endif

#ifdef WOLFSSL_FALCON_NTT_DSP
#include <arm_acle.h>
/* q replicated into both halfword lanes. */
#define FALCON_QPK (((word32)FALCON_Q << 16) | (word32)FALCON_Q)
/* Signed 16x16 -> 32 products (coefficients are < q < 2^14, so they fit s16). */
static WC_INLINE word32 falcon_smulbb(word32 a, word32 b) /* a.lo * b.lo */
    { return (word32)__smlabb(a, b, 0); }
static WC_INLINE word32 falcon_smultb(word32 a, word32 b) /* a.hi * b.lo */
    { return (word32)__smlatb(a, b, 0); }
static WC_INLINE word32 falcon_smultt(word32 a, word32 b) /* a.hi * b.hi */
    { return (word32)__smlatt(a, b, 0); }
static WC_INLINE word32 falcon_pack(word32 lo, word32 hi)
    { return (lo & 0xffffu) | (hi << 16); }
/* Two packed halfword lanes, each in [0, 2q) -> [0, q): USUB16 sets APSR.GE per
 * lane (set where x >= q), SEL then selects (x - q) on those lanes. */
static WC_INLINE word32 falcon_pcsub(word32 x)
    { word32 d = __usub16(x, FALCON_QPK); return __sel(d, x); }
/* Aliasing-safe packed load/store of a coefficient pair (lowers to LDR/STR). */
static WC_INLINE word32 falcon_ld2(const word16* p)
    { word32 v; XMEMCPY(&v, p, sizeof(v)); return v; }
static WC_INLINE void falcon_st2(word16* p, word32 v)
    { XMEMCPY(p, &v, sizeof(v)); }
#endif /* WOLFSSL_FALCON_NTT_DSP */

/* Forward negacyclic NTT, Cooley-Tukey: natural -> bit-reversed order. */
static void falcon_ntt(word16* a, int n, const word16* zetas)
{
    int t = n, m, i, j;
    for (m = 1; m < n; m <<= 1) {
        t >>= 1;
        for (i = 0; i < m; i++) {
            word32 z = zetas[m + i];
            int start = 2 * i * t;
#ifdef WOLFSSL_FALCON_NTT_DSP
            if (t >= 2) {
                for (j = start; j < start + t; j += 2) {
                    word32 A = falcon_ld2(a + j);       /* [a[j]   | a[j+1]]   */
                    word32 B = falcon_ld2(a + j + t);   /* [a[j+t] | a[j+1+t]] */
                    word32 v0 = falcon_barrett(falcon_smulbb(B, z));
                    word32 v1 = falcon_barrett(falcon_smultb(B, z));
                    word32 V = falcon_pack(v0, v1);
                    falcon_st2(a + j,     falcon_pcsub(__sadd16(A, V)));
                    falcon_st2(a + j + t,
                        falcon_pcsub(__ssub16(__sadd16(A, FALCON_QPK), V)));
                }
                continue;
            }
#endif
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = falcon_barrett((word32)a[j + t] * z);
                a[j]     = (word16)falcon_csub(u + v);
                a[j + t] = (word16)falcon_csub(u + FALCON_Q - v);
            }
        }
    }
}

/* Inverse negacyclic NTT, Gentleman-Sande: bit-reversed -> natural order. */
static void falcon_intt(word16* a, int n, const word16* izetas)
{
    int t = 1, m, i, j;
    word32 ninv;
    for (m = n; m > 1; m >>= 1) {
        int h = m >> 1;
        int j1 = 0;
        for (i = 0; i < h; i++) {
            word32 z = izetas[h + i];
            int start = j1;
#ifdef WOLFSSL_FALCON_NTT_DSP
            if (t >= 2) {
                for (j = start; j < start + t; j += 2) {
                    word32 A = falcon_ld2(a + j);
                    word32 B = falcon_ld2(a + j + t);
                    word32 W = falcon_pcsub(
                        __ssub16(__sadd16(A, FALCON_QPK), B)); /* csub(u+q-v) */
                    word32 w0 = falcon_barrett(falcon_smulbb(W, z));
                    word32 w1 = falcon_barrett(falcon_smultb(W, z));
                    falcon_st2(a + j,     falcon_pcsub(__sadd16(A, B)));
                    falcon_st2(a + j + t, falcon_pack(w0, w1));
                }
                j1 += 2 * t;
                continue;
            }
#endif
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = a[j + t];
                word32 w = falcon_csub(u + FALCON_Q - v);
                a[j]     = (word16)falcon_csub(u + v);
                a[j + t] = (word16)falcon_barrett(w * z);
            }
            j1 += 2 * t;
        }
        t <<= 1;
    }
    ninv = falcon_modinv((word32)n);
    for (j = 0; j < n; j++) {
        a[j] = (word16)falcon_barrett((word32)a[j] * ninv);
    }
}

/* ------------------------------------------------------------------------ */
/* Codec                                                                     */
/* ------------------------------------------------------------------------ */

/* Decode the public key polynomial h: n coefficients packed 14 bits each,
 * most-significant bit first. Each coefficient must be < q. Returns the number
 * of input bytes consumed, or a negative wolfCrypt error. */
static int falcon_modq_decode(const byte* in, word32 inLen, word16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t need = ((n * 14) + 7) >> 3;
    word32 acc = 0;
    int acc_bits = 0;
    size_t in_i = 0, out_i = 0;

    if (inLen < need) {
        return BUFFER_E;
    }
    while (out_i < n) {
        acc = (acc << 8) | in[in_i++];
        acc_bits += 8;
        if (acc_bits >= 14) {
            word32 w;
            acc_bits -= 14;
            w = (acc >> acc_bits) & 0x3FFF;
            if (w >= FALCON_Q) {
                return ASN_PARSE_E;
            }
            x[out_i++] = (word16)w;
        }
    }
    /* Unused trailing bits in the final byte must be zero. */
    if ((acc & (((word32)1 << acc_bits) - 1)) != 0) {
        return ASN_PARSE_E;
    }
    return (int)need;
}

/* Decode the compressed signature polynomial s2 (Golomb-Rice, k=7). Returns
 * the number of input bytes consumed, or a negative wolfCrypt error. Ported
 * from the Falcon reference comp_decode. */
static int falcon_comp_decode(const byte* in, word32 inLen, sword16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    word32 acc = 0;
    unsigned int acc_len = 0;
    size_t v = 0, u;

    for (u = 0; u < n; u++) {
        unsigned int b, s, mag;

        if (v >= inLen) {
            return BUFFER_E;
        }
        acc = (acc << 8) | (word32)in[v++];
        b = acc >> acc_len;
        s = b & 128;
        mag = b & 127;

        /* High bits: unary-coded run of zeros terminated by a one bit. */
        for (;;) {
            if (acc_len == 0) {
                if (v >= inLen) {
                    return BUFFER_E;
                }
                acc = (acc << 8) | (word32)in[v++];
                acc_len = 8;
            }
            acc_len--;
            if (((acc >> acc_len) & 1) != 0) {
                break;
            }
            mag += 128;
            if (mag > 2047) {
                return ASN_PARSE_E;
            }
        }
        /* Negative zero is not a valid encoding. */
        if (s != 0 && mag == 0) {
            return ASN_PARSE_E;
        }
        x[u] = (sword16)(s != 0 ? -(int)mag : (int)mag);
    }
    /* Unused trailing bits must be zero. */
    if ((acc & (((word32)1 << acc_len) - 1)) != 0) {
        return ASN_PARSE_E;
    }
    return (int)v;
}

/* hash-to-point (variable time; inputs are public). Absorbs nonce||msg into a
 * fresh SHAKE256 context and samples n coefficients in [0,q) by rejection. */
static int falcon_hash_to_point(const byte* nonce, const byte* msg,
        word32 msgLen, word16* c, unsigned logn, void* heap)
{
    wc_Shake shake;
    byte block[WC_SHA3_256_BLOCK_SIZE];
    byte* absorbBuf;
    size_t n = (size_t)1 << logn;
    size_t i = 0;
    int bi = WC_SHA3_256_BLOCK_SIZE;   /* force an initial squeeze */
    int ret;
    int shakeInit = 0;

    /* Guard against size_t wrap of (nonce || msg) on 32-bit targets. */
    if (msgLen > (word32)(0xFFFFFFFFUL - FALCON_NONCE_SIZE)) {
        return BAD_FUNC_ARG;
    }
    absorbBuf = (byte*)XMALLOC((size_t)FALCON_NONCE_SIZE + msgLen, heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (absorbBuf == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(absorbBuf, nonce, FALCON_NONCE_SIZE);
    if (msgLen > 0) {
        XMEMCPY(absorbBuf + FALCON_NONCE_SIZE, msg, msgLen);
    }

    ret = wc_InitShake256(&shake, heap, INVALID_DEVID);
    if (ret == 0) {
        shakeInit = 1;
        ret = wc_Shake256_Absorb(&shake, absorbBuf,
                (word32)(FALCON_NONCE_SIZE + msgLen));
    }

    while (ret == 0 && i < n) {
        word32 w;
        if (bi >= WC_SHA3_256_BLOCK_SIZE) {
            ret = wc_Shake256_SqueezeBlocks(&shake, block, 1);
            if (ret != 0) {
                break;
            }
            bi = 0;
        }
        w = ((word32)block[bi] << 8) | (word32)block[bi + 1];
        bi += 2;
        /* 61445 == 5 * q: keeps the distribution uniform mod q. */
        if (w < 61445u) {
            while (w >= FALCON_Q) {
                w -= FALCON_Q;
            }
            c[i++] = (word16)w;
        }
    }

    /* Only free the SHAKE context if it was successfully initialized
     * (wc_Shake256_Free touches device state in async builds). */
    if (shakeInit) {
        wc_Shake256_Free(&shake);
    }
    /* nonce || msg are public; no zeroization needed. */
    XFREE(absorbBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Center x (given in [0,q)) into (-q/2, q/2]. */
static WC_INLINE sword32 falcon_center(word32 x)
{
    sword32 r = (sword32)x;
    if (r > (FALCON_Q >> 1)) {
        r -= FALCON_Q;
    }
    return r;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

static int falcon_level_params(byte level, unsigned* logn, int* n, word32* pubSz)
{
    switch (level) {
        case FALCON_LEVEL1:
            *logn = FALCON_LEVEL1_LOGN;
            *n = FALCON_LEVEL1_N;
            *pubSz = FALCON_LEVEL1_PUB_KEY_SIZE;
            return 0;
        case FALCON_LEVEL5:
            *logn = FALCON_LEVEL5_LOGN;
            *n = FALCON_LEVEL5_N;
            *pubSz = FALCON_LEVEL5_PUB_KEY_SIZE;
            return 0;
        default:
            return BAD_FUNC_ARG;
    }
}

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
int falcon_native_make_key(falcon_key* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0, keySz = 0;
    sword8 *f = NULL, *g = NULL, *F = NULL, *G = NULL;
    word16* h = NULL;
    void* heap;

    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    keySz = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_KEY_SIZE
                                            : FALCON_LEVEL5_KEY_SIZE;
    heap = key->heap;

    f = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    g = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    F = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    G = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    h = (word16*)XMALLOC(sizeof(word16) * (size_t)n, heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (f == NULL || g == NULL || F == NULL || G == NULL || h == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    ret = falcon_keygen(rng, f, g, F, G, h, logn);
    if (ret != 0) {
        goto out;
    }

    /* Encode the public key: header byte then 14-bit packed h. */
    key->p[0] = (byte)(FALCON_PUB_HEAD | logn);
    if (falcon_modq_encode(key->p + 1, (size_t)(pubSz - 1), h, logn) == 0) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    /* Encode the secret key (header | f | g | F) into key->k. */
    if (falcon_privkey_encode(key->k, keySz, f, g, F, logn) != (size_t)keySz) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    key->pubKeySet = 1;
    key->prvKeySet = 1;

out:
    if (f != NULL) { ForceZero(f, (word32)n); XFREE(f, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (g != NULL) { ForceZero(g, (word32)n); XFREE(g, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (F != NULL) { ForceZero(F, (word32)n); XFREE(F, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (G != NULL) { ForceZero(G, (word32)n); XFREE(G, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (h != NULL) { XFREE(h, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    return ret;
}

int falcon_native_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen,
        falcon_key* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0, keySz = 0, sigMax = 0;
    sword8 *f = NULL, *g = NULL, *F = NULL, *G = NULL;
    word16* c = NULL;
    sword16* s2 = NULL;
    fpr *expanded = NULL, *tmp = NULL;
    falcon_sampler_ctx spc;
    byte nonce[FALCON_NONCE_SIZE];
    void* heap;
    int attempt, haveSpc = 0;
    size_t compLen = 0;

    if ((in == NULL && inLen != 0) || out == NULL || outLen == NULL ||
            key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!key->prvKeySet) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    keySz  = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_KEY_SIZE
                                             : FALCON_LEVEL5_KEY_SIZE;
    sigMax = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_SIG_SIZE
                                             : FALCON_LEVEL5_SIG_SIZE;
    if (*outLen < sigMax) {
        *outLen = sigMax;
        return BUFFER_E;
    }
    heap = key->heap;

    f  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    g  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    F  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    G  = (sword8*)XMALLOC((size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    c  = (word16*)XMALLOC(sizeof(word16) * (size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    s2 = (sword16*)XMALLOC(sizeof(sword16) * (size_t)n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    expanded = (fpr*)XMALLOC(sizeof(fpr) * FALCON_EXPANDED_KEY_FPR(logn), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    tmp = (fpr*)XMALLOC(sizeof(fpr) * FALCON_SIGN_TMP_FPR(logn), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (f == NULL || g == NULL || F == NULL || G == NULL || c == NULL ||
            s2 == NULL || expanded == NULL || tmp == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    /* Decode the secret basis, recompute G, expand to the ffLDL tree. */
    ret = falcon_privkey_decode(key->k, keySz, f, g, F, logn);
    if (ret != 0) {
        goto out;
    }
    ret = falcon_complete_private(G, f, g, F, logn, heap);
    if (ret != 0) {
        goto out;
    }
    ret = falcon_expand_privkey(expanded, f, g, F, G, logn, heap);
    if (ret != 0) {
        goto out;
    }
    ret = falcon_sampler_init(&spc, (int)logn, rng);
    if (ret != 0) {
        goto out;
    }
    haveSpc = 1;

    /* Each attempt draws a fresh nonce and samples a signature; retry if the
     * compressed form does not fit the level's maximum length. */
    for (attempt = 0; attempt < 32; attempt++) {
        ret = wc_RNG_GenerateBlock(rng, nonce, FALCON_NONCE_SIZE);
        if (ret != 0) {
            goto out;
        }
        ret = falcon_hash_to_point(nonce, in, inLen, c, logn, heap);
        if (ret != 0) {
            goto out;
        }
        ret = falcon_sign_core(&spc, expanded, c, s2, tmp, logn);
        if (ret != 0) {
            goto out;
        }
        out[0] = (byte)(FALCON_SIG_HEAD_COMPRESSED | logn);
        XMEMCPY(out + 1, nonce, FALCON_NONCE_SIZE);
        compLen = falcon_comp_encode(out + 1 + FALCON_NONCE_SIZE,
                (size_t)(*outLen - 1 - FALCON_NONCE_SIZE), s2, logn);
        if (compLen != 0) {
            break;
        }
    }
    if (compLen == 0) {
        ret = BUFFER_E;
        goto out;
    }
    *outLen = (word32)(1 + FALCON_NONCE_SIZE + compLen);

out:
    /* Always zeroize: the SHAKE sponge may hold seed-derived state even if
     * falcon_sampler_init failed after absorbing the seed. */
    (void)haveSpc;
    ForceZero(&spc, sizeof(spc));
    if (f != NULL)     { ForceZero(f, (word32)n); XFREE(f, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (g != NULL)     { ForceZero(g, (word32)n); XFREE(g, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (F != NULL)     { ForceZero(F, (word32)n); XFREE(F, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (G != NULL)     { ForceZero(G, (word32)n); XFREE(G, heap, DYNAMIC_TYPE_TMP_BUFFER); }
    if (s2 != NULL)    XFREE(s2, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (c != NULL)     XFREE(c, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (expanded != NULL) {
        ForceZero(expanded, (word32)(sizeof(fpr) * FALCON_EXPANDED_KEY_FPR(logn)));
        XFREE(expanded, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (tmp != NULL) {
        ForceZero(tmp, (word32)(sizeof(fpr) * FALCON_SIGN_TMP_FPR(logn)));
        XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

int falcon_native_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
        word32 msgLen, int* res, falcon_key* key)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0;
    const byte* sigData;
    word32 sigDataLen;
    word16* h = NULL;
    word16* c = NULL;
    word16* t = NULL;
    const word16* zetas = NULL;
    const word16* izetas = NULL;
    sword16* s2 = NULL;
    void* heap;

    if (sig == NULL || res == NULL || key == NULL ||
            (msg == NULL && msgLen != 0)) {
        return BAD_FUNC_ARG;
    }
    *res = 0;
    if (!key->pubKeySet) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    heap = key->heap;

    /* Signature framing: 1 header byte | 40-byte nonce | compressed s2. The
     * compressed encoding is variable length but bounded by the level's max. */
    if (sigLen < (word32)(1 + FALCON_NONCE_SIZE + 1)) {
        return BUFFER_E;
    }
    if (sigLen > (word32)(key->level == FALCON_LEVEL1 ?
            FALCON_LEVEL1_SIG_SIZE : FALCON_LEVEL5_SIG_SIZE)) {
        return BUFFER_E;
    }
    if (sig[0] != (byte)(FALCON_SIG_HEAD_COMPRESSED | logn)) {
        return ASN_PARSE_E;
    }
    sigData = sig + 1 + FALCON_NONCE_SIZE;
    sigDataLen = sigLen - 1 - FALCON_NONCE_SIZE;

    h      = (word16*)XMALLOC(sizeof(word16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    c      = (word16*)XMALLOC(sizeof(word16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    t      = (word16*)XMALLOC(sizeof(word16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    s2     = (sword16*)XMALLOC(sizeof(sword16) * n, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (h == NULL || c == NULL || t == NULL || s2 == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    /* Decode public key h (skip the 0x0n header byte). */
    if (key->p[0] != (byte)(FALCON_PUB_HEAD | logn)) {
        ret = ASN_PARSE_E;
        goto out;
    }
    {
        int rc = falcon_modq_decode(key->p + 1, pubSz - 1, h, logn);
        if (rc < 0) {
            ret = rc;
            goto out;
        }
    }

    /* Decode compressed s2; the encoding must consume the whole buffer. */
    {
        int rc = falcon_comp_decode(sigData, sigDataLen, s2, logn);
        if (rc < 0) {
            ret = rc;
            goto out;
        }
        if ((word32)rc != sigDataLen) {
            ret = ASN_PARSE_E;
            goto out;
        }
    }

    /* c = HashToPoint(nonce || msg). */
    ret = falcon_hash_to_point(sig + 1, msg, msgLen, c, logn, heap);
    if (ret != 0) {
        goto out;
    }

    /* t = s2 * h mod (x^n + 1) mod q, via NTT. Twiddle tables are cached. */
    falcon_get_tables(logn, &zetas, &izetas);
    {
        int i;
        for (i = 0; i < n; i++) {
            sword32 v = s2[i];
            if (v < 0) {
                v += FALCON_Q;
            }
            t[i] = (word16)v;
        }
    }
    falcon_ntt(t, n, zetas);
    falcon_ntt(h, n, zetas);
    {
        int i = 0;
#ifdef WOLFSSL_FALCON_NTT_DSP
        for (; i + 1 < n; i += 2) {
            word32 T = falcon_ld2(t + i);
            word32 H = falcon_ld2(h + i);
            word32 p0 = falcon_barrett(falcon_smulbb(T, H));
            word32 p1 = falcon_barrett(falcon_smultt(T, H));
            falcon_st2(t + i, falcon_pack(p0, p1));
        }
#endif
        for (; i < n; i++) {
            t[i] = (word16)falcon_barrett((word32)t[i] * h[i]);
        }
    }
    falcon_intt(t, n, izetas);

    /* s1 = c - s2*h mod q (centered); accept iff ||(s1,s2)||^2 <= bound. */
    {
        word64 norm = 0;
        int i = 0;
#ifdef WOLFSSL_FALCON_NTT_DSP
        /* Accumulate two squared coefficients per SMUAD (a.lo^2 + a.hi^2).
         * |centered| <= q/2 < 2^13, so each SMUAD result < 2^27 (no overflow);
         * the running total is 64-bit. */
        for (; i + 1 < n; i += 2) {
            word32 d0 = falcon_csub(c[i]     + FALCON_Q - t[i]);
            word32 d1 = falcon_csub(c[i + 1] + FALCON_Q - t[i + 1]);
            word32 s1p = falcon_pack((word32)(sword16)falcon_center(d0),
                                     (word32)(sword16)falcon_center(d1));
            word32 s2p = falcon_pack((word32)(sword16)s2[i],
                                     (word32)(sword16)s2[i + 1]);
            norm += (word64)(word32)__smuad(s1p, s1p);
            norm += (word64)(word32)__smuad(s2p, s2p);
        }
#endif
        for (; i < n; i++) {
            word32 d = falcon_csub(c[i] + FALCON_Q - t[i]);
            sword32 s1c = falcon_center(d);
            sword32 s2c = s2[i];
            norm += (word64)((sword64)s1c * s1c);
            norm += (word64)((sword64)s2c * s2c);
        }
        if (norm <= (word64)falcon_l2bound[logn]) {
            *res = 1;
        }
    }

out:
    if (h != NULL)      XFREE(h, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (c != NULL)      XFREE(c, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (t != NULL)      XFREE(t, heap, DYNAMIC_TYPE_TMP_BUFFER);
    /* zetas/izetas point at static caches; not freed. */
    if (s2 != NULL)     XFREE(s2, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}


#endif /* HAVE_FALCON */
