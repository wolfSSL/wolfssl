/* Native.cs
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

using System;
using System.Runtime.InteropServices;

namespace wolfSSL.CSharp.Fips
{
    /* Structure identifiers understood by the native size helper
     * (native/fips_sizes.c). Values are ABI; append only. */
    internal enum FipsStructType
    {
        Rng = 0, Aes = 1, Rsa = 2, Ecc = 3, Dh = 4,
        Sha = 5, Sha224 = 6, Sha256 = 7, Sha384 = 8, Sha512 = 9,
        Sha3 = 10, Hmac = 11, Cmac = 12,
        Tls13LabelMax = 13,  /* MAX_TLS13_HKDF_LABEL_SZ, not a struct */
        FipsVersionMM = 14,  /* build fingerprint: FIPS major * 100 + minor */
        LibCrc = 15,         /* cksum CRC of the libwolfssl the helper was built for */
        LibSize = 16,        /* size of that libwolfssl file */
        /* 17, 18 and 20 retired (devId offsets); values are ABI, not reused */
        RngMaxBlockLen = 19, /* RNG_MAX_BLOCK_LEN */
        ValidateEccImport = 21 /* 1 if WOLFSSL_VALIDATE_ECC_IMPORT */
    }

    /* Bind only _fips names: DllImport skips the fips.h redirection, so plain wc_*
     * would bypass status and CAST gating. tools/fips-bind-audit.sh checks this. */
    internal static class Native
    {
        internal const string WOLFSSL = "wolfssl";
        internal const string SIZES = "wolfssl_csharp_fips";

        /* ---- size helper (outside the module boundary) ---- */
        [DllImport(SIZES, EntryPoint = "wc_csharp_fips_sizeof", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SizeOf(int type);

        /* ---- module status and self-test services (fips_test.h / fips.h) ---- */
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void FipsCallback(int ok, int err, IntPtr hash);

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_SetCb_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_SetCb_fips(FipsCallback cb);

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_GetStatus_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_GetStatus_fips();

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_GetMode_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_GetMode_fips();

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_GetCoreHash_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr wolfCrypt_GetCoreHash_fips();

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_GetVersion_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr wolfCrypt_GetVersion_fips();

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_IntegrityTest_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_IntegrityTest_fips();

        [DllImport(WOLFSSL, EntryPoint = "wc_RunCast_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RunCast_fips(int castId);

        [DllImport(WOLFSSL, EntryPoint = "wc_GetCastStatus_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_GetCastStatus_fips(int castId);

        [DllImport(WOLFSSL, EntryPoint = "wc_RunAllCast_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RunAllCast_fips();

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_SetPrivateKeyReadEnable_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_SetPrivateKeyReadEnable_fips(int enable, int keyType);

        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_GetPrivateKeyReadEnable_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_GetPrivateKeyReadEnable_fips(int keyType);

        /* DRBG seed source (WC_RNG_SEED_CB builds). cb is a native wc_RngSeed_Cb:
         * int (*)(OS_Seed* os, byte* seed, word32 sz). */
        [DllImport(WOLFSSL, EntryPoint = "wc_SetSeed_Cb_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_SetSeed_Cb_fips(IntPtr cb);

        /* OS entropy export, found with NativeLibrary.GetExport and passed to
         * wc_SetSeed_Cb_fips as a pointer; never called from C#. */
        internal const string OS_SEED_EXPORT = "wc_GenerateSeed";

        /* ---- Hash_DRBG (SP 800-90A) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitRng_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitRng_fips(FipsHandle rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitRngNonce_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitRngNonce_fips(FipsHandle rng, byte[] nonce, uint nonceSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_FreeRng_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_FreeRng_fips(IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_RNG_GenerateBlock_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RNG_GenerateBlock_fips(FipsHandle rng, byte[] output, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_RNG_HealthTest_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RNG_HealthTest_fips(int reseed, byte[] seedA, uint seedASz,
            byte[]? seedB, uint seedBSz, byte[] output, uint outputSz);

        /* ---- SHA-1, SHA-2, SHA-3 (FIPS 180-4, FIPS 202) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha_fips(FipsHandle sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_ShaUpdate_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ShaUpdate_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_ShaFinal_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ShaFinal_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_ShaFree_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_ShaFree_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha224_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha224_fips(FipsHandle sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha224Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha224Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha224Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha224Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha224Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha224Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha256_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha256_fips(FipsHandle sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha256Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha256Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha256Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha256Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha256Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha256Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha384_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha384_fips(FipsHandle sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha384Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha384Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha384Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha384Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha384Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha384Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha512_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha512_fips(FipsHandle sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha512Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha512Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha512Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha512Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha512Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha512Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_224_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_224_fips(FipsHandle sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_224_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_224_Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_224_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_224_Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_224_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_224_Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_256_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_256_fips(FipsHandle sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_256_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_256_Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_256_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_256_Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_256_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_256_Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_384_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_384_fips(FipsHandle sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_384_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_384_Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_384_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_384_Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_384_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_384_Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_512_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_512_fips(FipsHandle sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_512_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_512_Update_fips(FipsHandle sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_512_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_512_Final_fips(FipsHandle sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_512_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_512_Free_fips(IntPtr sha);

        /* ---- HMAC (FIPS 198-1) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_HmacSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HmacSetKey_fips(FipsHandle hmac, int type, byte[] key, uint keySz);

        [DllImport(WOLFSSL, EntryPoint = "wc_HmacUpdate_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HmacUpdate_fips(FipsHandle hmac, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_HmacFinal_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HmacFinal_fips(FipsHandle hmac, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_HmacFree_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_HmacFree_fips(IntPtr hmac);

        /* ---- CMAC-AES (SP 800-38B) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitCmac_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitCmac_fips(FipsHandle cmac, byte[] key, uint keySz, int type, IntPtr unused);

        [DllImport(WOLFSSL, EntryPoint = "wc_CmacUpdate_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_CmacUpdate_fips(FipsHandle cmac, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_CmacFinal_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_CmacFinal_fips(FipsHandle cmac, byte[] tag, ref uint tagSz);

        /* ---- AES (FIPS 197; SP 800-38A/B/C/D) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_AesSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesSetKey_fips(FipsHandle aes, byte[] key, uint len, byte[]? iv, int dir);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesSetIV_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesSetIV_fips(FipsHandle aes, byte[]? iv);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesEcbEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesEcbEncrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesEcbDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesEcbDecrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCbcEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCbcEncrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCbcDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCbcDecrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesOfbEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesOfbEncrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesOfbDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesOfbDecrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCtrSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCtrSetKey_fips(FipsHandle aes, byte[] key, uint len, byte[]? iv, int dir);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCtrEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCtrEncrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmSetKey_fips(FipsHandle aes, byte[] key, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmSetExtIV_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmSetExtIV_fips(FipsHandle aes, byte[] iv, uint ivSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmSetIV_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmSetIV_fips(FipsHandle aes, uint ivSz, byte[]? ivFixed, uint ivFixedSz, FipsHandle rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmEncrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz, byte[] ivOut, uint ivOutSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmDecrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz, byte[] iv, uint ivSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_Gmac_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Gmac_fips(byte[] key, uint keySz, byte[] iv, uint ivSz, byte[] authIn, uint authInSz, byte[] authTag, uint authTagSz, FipsHandle rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_GmacVerify_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_GmacVerify_fips(byte[] key, uint keySz, byte[] iv, uint ivSz, byte[] authIn, uint authInSz, byte[] authTag, uint authTagSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmSetKey_fips(FipsHandle aes, byte[] key, uint keySz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmSetNonce_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmSetNonce_fips(FipsHandle aes, byte[] nonce, uint nonceSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmEncrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz, byte[] ivOut, uint ivOutSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmDecrypt_fips(FipsHandle aes, byte[] output, byte[] input, uint sz, byte[] nonce, uint nonceSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        /* ---- RSA (FIPS 186-4/5, SP 800-56B) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitRsaKey_fips(FipsHandle key, IntPtr heap);

        [DllImport(WOLFSSL, EntryPoint = "wc_FreeRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_FreeRsaKey_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_MakeRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_MakeRsaKey_fips(FipsHandle key, int size, CLong e, FipsHandle rng);   /* C long: 32-bit on Windows and 32-bit targets */

        [DllImport(WOLFSSL, EntryPoint = "wc_CheckRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_CheckRsaKey_fips(FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaEncryptSize_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaEncryptSize_fips(FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaExportKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaExportKey_fips(FipsHandle key, byte[] e, ref uint eSz, byte[] n, ref uint nSz, byte[] d, ref uint dSz, byte[] p, ref uint pSz, byte[] q, ref uint qSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaSSL_Sign_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaSSL_Sign_fips(byte[] input, uint inLen, byte[] output, uint outLen, FipsHandle key, FipsHandle rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaSSL_Verify_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaSSL_Verify_fips(byte[] input, uint inLen, byte[] output, uint outLen, FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPSS_SignEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPSS_SignEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, int hash, int mgf, int saltLen, FipsHandle key, FipsHandle rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPSS_VerifyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPSS_VerifyEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, int hash, int mgf, int saltLen, FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPSS_CheckPaddingEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPSS_CheckPaddingEx_fips(byte[] input, uint inSz, byte[] sig, uint sigSz, int hashType, int saltLen, int bits);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPublicEncryptEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPublicEncryptEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, FipsHandle key, FipsHandle rng, int type, int hash, int mgf, byte[]? label, uint labelSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPrivateDecryptEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPrivateDecryptEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, FipsHandle key, int type, int hash, int mgf, byte[]? label, uint labelSz);

        /* ---- ECC: ECDSA (FIPS 186), ECC CDH (SP 800-56A) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_init_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_init_fips(FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_free_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_set_rng_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_set_rng_fips(FipsHandle key, FipsHandle rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_check_key_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_check_key_fips(FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_make_key_ex_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_make_key_ex_fips(FipsHandle rng, int keysize, FipsHandle key, int curveId);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_export_x963_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_export_x963_fips(FipsHandle key, byte[] output, ref uint outLen);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_import_x963_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_import_x963_fips(byte[] input, uint inLen, FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_shared_secret_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_shared_secret_fips(FipsHandle privateKey, FipsHandle publicKey, byte[] output, ref uint outLen);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_sign_hash_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_sign_hash_fips(byte[] input, uint inLen, byte[] output, ref uint outLen, FipsHandle rng, FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_verify_hash_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_verify_hash_fips(byte[] sig, uint sigLen, byte[] hash, uint hashLen, out int res, FipsHandle key);

        /* ---- Finite field DH (SP 800-56A) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitDhKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitDhKey_fips(FipsHandle key);

        [DllImport(WOLFSSL, EntryPoint = "wc_FreeDhKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_FreeDhKey_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhSetKeyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhSetKeyEx_fips(FipsHandle key, byte[] p, uint pSz, byte[] g, uint gSz, byte[]? q, uint qSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhSetNamedKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhSetNamedKey_fips(FipsHandle key, int name);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhGenerateKeyPair_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhGenerateKeyPair_fips(FipsHandle key, FipsHandle rng, byte[] priv, ref uint privSz, byte[] pub, ref uint pubSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhCheckPubKeyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhCheckPubKeyEx_fips(FipsHandle key, byte[] pub, uint pubSz, byte[]? prime, uint primeSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhCheckPrivKeyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhCheckPrivKeyEx_fips(FipsHandle key, byte[] priv, uint privSz, byte[]? prime, uint primeSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhCheckKeyPair_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhCheckKeyPair_fips(FipsHandle key, byte[] pub, uint pubSz, byte[] priv, uint privSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhAgree_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhAgree_fips(FipsHandle key, byte[] agree, ref uint agreeSz, byte[] priv, uint privSz, byte[] otherPub, uint pubSz);

        /* ---- KDFs (SP 800-135, SP 800-56C, RFC 5869) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_PRF_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_PRF_fips(byte[] result, uint resLen, byte[] secret, uint secLen, byte[] seed, uint seedLen, int macType, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_PRF_TLSv12_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_PRF_TLSv12_fips(byte[] result, uint resLen, byte[] secret, uint secLen, byte[] label, uint labLen, byte[] seed, uint seedLen, int useAtLeastSha256, int macType, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_HKDF_Extract_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HKDF_Extract_fips(int type, byte[]? salt, uint saltSz, byte[] inKey, uint inKeySz, byte[] output);

        [DllImport(WOLFSSL, EntryPoint = "wc_HKDF_Expand_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HKDF_Expand_fips(int type, byte[] inKey, uint inKeySz, byte[]? info, uint infoSz, byte[] output, uint outSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_HKDF_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HKDF_fips(int type, byte[] inKey, uint inKeySz, byte[]? salt, uint saltSz, byte[]? info, uint infoSz, byte[] output, uint outSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_Tls13_HKDF_Extract_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Tls13_HKDF_Extract_fips(byte[] prk, byte[]? salt, int saltLen, byte[] ikm, int ikmLen, int digest);

        [DllImport(WOLFSSL, EntryPoint = "wc_Tls13_HKDF_Expand_Label_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Tls13_HKDF_Expand_Label_fips(byte[] okm, uint okmLen, byte[] prk, uint prkLen, byte[] protocol, uint protocolLen, byte[] label, uint labelLen, byte[] info, uint infoLen, int digest);

        [DllImport(WOLFSSL, EntryPoint = "wc_SSH_KDF_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_SSH_KDF_fips(byte hashId, byte keyId, byte[] key, uint keySz, byte[] k, uint kSz, byte[] h, uint hSz, byte[] sessionId, uint sessionIdSz);

        /* Only exported by libraries built with HAVE_FORCE_FIPS_FAILURE
         * (operational-test builds). Used by the negative tests. */
        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_SetStatus_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_SetStatus_fips(int status);
    }
}
