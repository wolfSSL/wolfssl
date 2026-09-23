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
        Sha3 = 10, Hmac = 11, Cmac = 12
    }

    /* All native bindings for the FIPS wrapper.
     *
     * Every cryptographic binding in this file targets an in-boundary
     * wolfCrypt FIPS v5.2.3 entry point by its exported _fips name. The
     * plain wc_* names are never bound: a C# DllImport resolves names at
     * runtime and does not see the fips.h #define redirection, so binding the
     * plain name would call the implementation directly and bypass the FIPS
     * service layer (status and CAST gating).
     *
     * tools/fips-bind-audit.sh checks that every EntryPoint in this file
     * ends in _fips, except for the size helper. */
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

        /* DRBG seed source registration (WC_RNG_SEED_CB builds). cb is a
         * native function pointer of type wc_RngSeed_Cb:
         * int (*)(OS_Seed* os, byte* seed, word32 sz). */
        [DllImport(WOLFSSL, EntryPoint = "wc_SetSeed_Cb_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_SetSeed_Cb_fips(IntPtr cb);

        /* Name of the library's OS entropy function (/dev/urandom on Linux).
         * Looked up with NativeLibrary.GetExport and passed to
         * wc_SetSeed_Cb_fips as a function pointer; it is never called from
         * C#, so it is not declared as a DllImport. */
        internal const string OS_SEED_EXPORT = "wc_GenerateSeed";

        /* ---- Hash_DRBG (SP 800-90A) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitRng_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitRng_fips(IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitRngNonce_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitRngNonce_fips(IntPtr rng, byte[] nonce, uint nonceSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_FreeRng_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_FreeRng_fips(IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_RNG_GenerateBlock_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RNG_GenerateBlock_fips(IntPtr rng, byte[] output, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_RNG_HealthTest_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RNG_HealthTest_fips(int reseed, byte[] seedA, uint seedASz,
            byte[]? seedB, uint seedBSz, byte[] output, uint outputSz);

        /* ---- SHA-1, SHA-2, SHA-3 (FIPS 180-4, FIPS 202) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_ShaUpdate_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ShaUpdate_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_ShaFinal_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ShaFinal_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_ShaFree_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_ShaFree_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha224_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha224_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha224Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha224Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha224Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha224Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha224Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha224Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha256_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha256_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha256Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha256Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha256Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha256Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha256Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha256Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha384_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha384_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha384Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha384Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha384Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha384Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha384Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha384Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha512_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha512_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha512Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha512Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha512Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha512Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha512Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha512Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_224_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_224_fips(IntPtr sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_224_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_224_Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_224_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_224_Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_224_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_224_Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_256_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_256_fips(IntPtr sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_256_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_256_Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_256_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_256_Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_256_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_256_Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_384_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_384_fips(IntPtr sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_384_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_384_Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_384_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_384_Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_384_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_384_Free_fips(IntPtr sha);

        [DllImport(WOLFSSL, EntryPoint = "wc_InitSha3_512_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitSha3_512_fips(IntPtr sha, IntPtr heap, int devId);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_512_Update_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_512_Update_fips(IntPtr sha, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_512_Final_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Sha3_512_Final_fips(IntPtr sha, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_Sha3_512_Free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_Sha3_512_Free_fips(IntPtr sha);

        /* ---- HMAC (FIPS 198-1) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_HmacSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HmacSetKey_fips(IntPtr hmac, int type, byte[] key, uint keySz);

        [DllImport(WOLFSSL, EntryPoint = "wc_HmacUpdate_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HmacUpdate_fips(IntPtr hmac, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_HmacFinal_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_HmacFinal_fips(IntPtr hmac, byte[] hash);

        [DllImport(WOLFSSL, EntryPoint = "wc_HmacFree_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void wc_HmacFree_fips(IntPtr hmac);

        /* ---- CMAC-AES (SP 800-38B) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitCmac_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitCmac_fips(IntPtr cmac, byte[] key, uint keySz, int type, IntPtr unused);

        [DllImport(WOLFSSL, EntryPoint = "wc_CmacUpdate_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_CmacUpdate_fips(IntPtr cmac, byte[] data, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_CmacFinal_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_CmacFinal_fips(IntPtr cmac, byte[] tag, ref uint tagSz);

        /* ---- AES (FIPS 197; SP 800-38A/B/C/D) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_AesSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesSetKey_fips(IntPtr aes, byte[] key, uint len, byte[]? iv, int dir);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesSetIV_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesSetIV_fips(IntPtr aes, byte[]? iv);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesEcbEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesEcbEncrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesEcbDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesEcbDecrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCbcEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCbcEncrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCbcDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCbcDecrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesOfbEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesOfbEncrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesOfbDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesOfbDecrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCtrSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCtrSetKey_fips(IntPtr aes, byte[] key, uint len, byte[]? iv, int dir);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCtrEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCtrEncrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmSetKey_fips(IntPtr aes, byte[] key, uint len);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmSetExtIV_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmSetExtIV_fips(IntPtr aes, byte[] iv, uint ivSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmSetIV_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmSetIV_fips(IntPtr aes, uint ivSz, byte[]? ivFixed, uint ivFixedSz, IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmEncrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz, byte[] ivOut, uint ivOutSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesGcmDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesGcmDecrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz, byte[] iv, uint ivSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_Gmac_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_Gmac_fips(byte[] key, uint keySz, byte[] iv, uint ivSz, byte[] authIn, uint authInSz, byte[] authTag, uint authTagSz, IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_GmacVerify_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_GmacVerify_fips(byte[] key, uint keySz, byte[] iv, uint ivSz, byte[] authIn, uint authInSz, byte[] authTag, uint authTagSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmSetKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmSetKey_fips(IntPtr aes, byte[] key, uint keySz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmSetNonce_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmSetNonce_fips(IntPtr aes, byte[] nonce, uint nonceSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmEncrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmEncrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz, byte[] ivOut, uint ivOutSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_AesCcmDecrypt_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_AesCcmDecrypt_fips(IntPtr aes, byte[] output, byte[] input, uint sz, byte[] nonce, uint nonceSz, byte[] authTag, uint authTagSz, byte[] authIn, uint authInSz);

        /* ---- RSA (FIPS 186-4/5, SP 800-56B) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitRsaKey_fips(IntPtr key, IntPtr heap);

        [DllImport(WOLFSSL, EntryPoint = "wc_FreeRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_FreeRsaKey_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_MakeRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_MakeRsaKey_fips(IntPtr key, int size, long e, IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_CheckRsaKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_CheckRsaKey_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaEncryptSize_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaEncryptSize_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaExportKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaExportKey_fips(IntPtr key, byte[] e, ref uint eSz, byte[] n, ref uint nSz, byte[] d, ref uint dSz, byte[] p, ref uint pSz, byte[] q, ref uint qSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaSSL_Sign_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaSSL_Sign_fips(byte[] input, uint inLen, byte[] output, uint outLen, IntPtr key, IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaSSL_Verify_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaSSL_Verify_fips(byte[] input, uint inLen, byte[] output, uint outLen, IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPSS_SignEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPSS_SignEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, int hash, int mgf, int saltLen, IntPtr key, IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPSS_VerifyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPSS_VerifyEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, int hash, int mgf, int saltLen, IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPSS_CheckPaddingEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPSS_CheckPaddingEx_fips(byte[] input, uint inSz, byte[] sig, uint sigSz, int hashType, int saltLen, int bits);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPublicEncryptEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPublicEncryptEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, IntPtr key, IntPtr rng, int type, int hash, int mgf, byte[]? label, uint labelSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_RsaPrivateDecryptEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_RsaPrivateDecryptEx_fips(byte[] input, uint inLen, byte[] output, uint outLen, IntPtr key, int type, int hash, int mgf, byte[]? label, uint labelSz);

        /* ---- ECC: ECDSA (FIPS 186), ECC CDH (SP 800-56A) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_init_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_init_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_free_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_free_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_set_rng_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_set_rng_fips(IntPtr key, IntPtr rng);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_check_key_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_check_key_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_make_key_ex_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_make_key_ex_fips(IntPtr rng, int keysize, IntPtr key, int curveId);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_export_x963_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_export_x963_fips(IntPtr key, byte[] output, ref uint outLen);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_import_x963_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_import_x963_fips(byte[] input, uint inLen, IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_shared_secret_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_shared_secret_fips(IntPtr privateKey, IntPtr publicKey, byte[] output, ref uint outLen);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_sign_hash_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_sign_hash_fips(byte[] input, uint inLen, byte[] output, ref uint outLen, IntPtr rng, IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_ecc_verify_hash_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_ecc_verify_hash_fips(byte[] sig, uint sigLen, byte[] hash, uint hashLen, out int res, IntPtr key);

        /* ---- Finite field DH (SP 800-56A) ---- */
        [DllImport(WOLFSSL, EntryPoint = "wc_InitDhKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_InitDhKey_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_FreeDhKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_FreeDhKey_fips(IntPtr key);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhSetKeyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhSetKeyEx_fips(IntPtr key, byte[] p, uint pSz, byte[] g, uint gSz, byte[]? q, uint qSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhSetNamedKey_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhSetNamedKey_fips(IntPtr key, int name);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhGenerateKeyPair_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhGenerateKeyPair_fips(IntPtr key, IntPtr rng, byte[] priv, ref uint privSz, byte[] pub, ref uint pubSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhCheckPubKeyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhCheckPubKeyEx_fips(IntPtr key, byte[] pub, uint pubSz, byte[]? prime, uint primeSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhCheckPrivKeyEx_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhCheckPrivKeyEx_fips(IntPtr key, byte[] priv, uint privSz, byte[]? prime, uint primeSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhCheckKeyPair_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhCheckKeyPair_fips(IntPtr key, byte[] pub, uint pubSz, byte[] priv, uint privSz);

        [DllImport(WOLFSSL, EntryPoint = "wc_DhAgree_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhAgree_fips(IntPtr key, byte[] agree, ref uint agreeSz, byte[] priv, uint privSz, byte[] otherPub, uint pubSz);

        /* v5.2.3 only (not in the v5.2.1 boundary) */
        [DllImport(WOLFSSL, EntryPoint = "wc_DhGeneratePublic_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wc_DhGeneratePublic_fips(IntPtr key, byte[] priv, uint privSz, byte[] pub, ref uint pubSz);

        /* Only exported by libraries built with HAVE_FORCE_FIPS_FAILURE
         * (operational-test builds). Used by the negative tests. */
        [DllImport(WOLFSSL, EntryPoint = "wolfCrypt_SetStatus_fips", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wolfCrypt_SetStatus_fips(int status);
    }
}
