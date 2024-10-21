/* wolfCrypt.cs
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
using System.Security.Cryptography;
using System.Text;

namespace wolfSSL.CSharp
{
    public class wolfcrypt
    {
        private const string wolfssl_dll = "wolfssl.dll";

        /********************************
         * Init wolfSSL library
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wolfCrypt_Init();
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wolfCrypt_Cleanup();


        /********************************
         * Random
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_rng_new(IntPtr nonce, UInt32 nonceSz, IntPtr heap);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void wc_rng_free(IntPtr rng);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RNG_GenerateBlock(IntPtr rng, IntPtr output, UInt32 sz);


        /********************************
         * ECC
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_ecc_key_new(IntPtr heap);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void wc_ecc_key_free(IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_set_rng(IntPtr key, IntPtr rng);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_make_key_ex(IntPtr rng, int keysize, IntPtr key, int curve_id);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_sign_hash(IntPtr hashPtr, uint hashlen, IntPtr sigPtr, IntPtr siglen, IntPtr rng, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_verify_hash(IntPtr sigPtr, uint siglen, IntPtr hashPtr, uint hashlen, IntPtr res, IntPtr key);

        /* ASN.1 DER format */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_EccPrivateKeyDecode(IntPtr keyBuf, IntPtr idx, IntPtr key, uint keyBufSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_EccPublicKeyDecode(byte[] input, ref uint inOutIdx, IntPtr key, uint inSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_EccPrivateKeyToDer(IntPtr key, byte[] output, uint inLen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_EccPublicKeyToDer(IntPtr key, byte[] output, uint inLen, int with_AlgCurve);


        /********************************
         * ECIES
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_ecc_ctx_new(int flags, IntPtr rng);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_ecc_ctx_new_ex(int flags, IntPtr rng, IntPtr heap);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void wc_ecc_ctx_free(IntPtr ctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_ctx_reset(IntPtr ctx, IntPtr rng);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_ctx_set_algo(IntPtr ctx, byte encAlgo, byte kdfAlgo, byte macAlgo);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_ecc_ctx_get_own_salt(IntPtr ctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_ctx_set_peer_salt(IntPtr ctx, IntPtr salt);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_ctx_set_own_salt(IntPtr ctx, IntPtr salt, uint sz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_ctx_set_kdf_salt(IntPtr ctx, IntPtr salt, uint sz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_ctx_set_info(IntPtr ctx, IntPtr info, int sz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_encrypt(IntPtr privKey, IntPtr pubKey, IntPtr msg, uint msgSz, IntPtr outBuffer, IntPtr outSz, IntPtr ctx);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_encrypt_ex(IntPtr privKey, IntPtr pubKey, IntPtr msg, uint msgSz, IntPtr outBuffer, IntPtr outSz, IntPtr ctx, int compressed);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_decrypt(IntPtr privKey, IntPtr pubKey, IntPtr msg, uint msgSz, IntPtr outBuffer, IntPtr outSz, IntPtr ctx);


        /********************************
         * ECDHE
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_shared_secret(IntPtr privateKey, IntPtr publicKey, byte[] outSharedSecret, ref int outlen);


        /********************************
         * RSA
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr wc_NewRsaKey(IntPtr heap, int devId, IntPtr result_code);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_DeleteRsaKey(IntPtr key, IntPtr key_p);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_InitRsaKey(IntPtr key, IntPtr heap);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void wc_FreeRsaKey(IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_MakeRsaKey(IntPtr key, int keysize, Int32 exponent, IntPtr rng);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaSSL_Sign(IntPtr hashPtr, int hashLen, IntPtr sigPtr, int sigLen, IntPtr key, IntPtr rng);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaSSL_Verify(IntPtr sigPtr, int sigLen, IntPtr hashPtr, int hashLen, IntPtr key);

        /* ASN.1 DER format */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaPublicEncrypt(IntPtr inPtr, int inLen, IntPtr outPtr, int outLen, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaPrivateDecrypt(IntPtr inPtr, int inLen, IntPtr outPtr, int outLen, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaPrivateKeyDecode(IntPtr keyBuf, IntPtr idx, IntPtr key, uint keyBufSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaPublicKeyDecode(IntPtr keyBuf, IntPtr idx, IntPtr key, uint keyBufSz);

        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaPSS_Sign(IntPtr hashPtr, int hashLen, IntPtr sigPtr, int sigLen, int hashType, IntPtr rng, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaPSS_Verify(IntPtr sigPtr, int sigLen, IntPtr hashPtr, int hashLen, int hashType, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_RsaPSS_CheckPadding(IntPtr sigPtr, int sigLen, int hashType, IntPtr key);


        /********************************
         * ED25519
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr wc_ed25519_new(IntPtr heap, int devId, IntPtr result_code);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_delete(IntPtr key, IntPtr key_p);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_init(IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern void wc_ed25519_free(IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_make_key(IntPtr rng, int keysize, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_sign_msg(IntPtr inMsg, uint inlen, IntPtr outMsg, ref uint outlen, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_verify_msg(IntPtr sig, uint siglen, IntPtr msg, uint msgLen, ref int ret, IntPtr key);

        /* ASN.1 DER format */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Ed25519PrivateKeyDecode(byte[] input, ref uint inOutIdx, IntPtr key, uint inSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Ed25519PublicKeyDecode(byte[] input, ref uint inOutIdx, IntPtr key, uint inSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Ed25519KeyToDer(IntPtr key, byte[] output, uint inLen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Ed25519PrivateKeyToDer(IntPtr key, byte[] output, uint inLen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Ed25519PublicKeyToDer(IntPtr key, byte[] output, uint inLen, int withAlg);

        /* RAW format */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_make_public(IntPtr key, IntPtr pubKey, uint pubKeySz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_import_public(IntPtr inMsg, uint inLen, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_export_public(IntPtr key, IntPtr outMsg, ref uint outLen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_export_private(IntPtr key, IntPtr outMsg, ref uint outLen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_ed25519_size(IntPtr key);


        /********************************
         * Curve25519
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr wc_curve25519_new(IntPtr heap, int devId, IntPtr result_code);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_curve25519_delete(IntPtr key, IntPtr key_p);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_init(IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static void wc_curve25519_free(IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_make_key(IntPtr rng, int keysize, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_shared_secret(IntPtr privateKey, IntPtr publicKey, byte[] outSharedSecret, ref int outlen);

        /* ASN.1 DER format */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Curve25519PrivateKeyDecode(byte[] input, ref uint inOutIdx, IntPtr key, uint inSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Curve25519PublicKeyDecode(byte[] input, ref uint inOutIdx, IntPtr key, uint inSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Curve25519PrivateKeyToDer(IntPtr key, byte[] output, uint inLen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_Curve25519PublicKeyToDer(IntPtr key, byte[] output, uint inLen, int withAlg);

        /* RAW format */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_import_private(IntPtr privKey, int privKeySz, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_curve25519_export_public(IntPtr key, byte[] outBuffer, ref uint outLen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_import_public(IntPtr pubKey, int pubKeySz, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_export_public(IntPtr key, IntPtr outPubKey, ref int outlen);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private static extern int wc_curve25519_export_key_raw(IntPtr key, byte[] priv, ref uint privSz, byte[] pub, ref uint pubSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_import_private_raw(IntPtr privKey, IntPtr pubKey, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_curve25519_export_private_raw(IntPtr key, IntPtr outPrivKey, IntPtr outPubKey);


        /********************************
         * AES-GCM
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_AesNew(IntPtr heap, int devId, IntPtr result_code);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_AesDelete(IntPtr aes, IntPtr aes_p);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_AesFree(IntPtr aes);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_AesInit(IntPtr aes, IntPtr heap, int devId);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_AesGcmInit(IntPtr aes, IntPtr key, uint len, IntPtr iv, uint ivSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_AesGcmSetKey(IntPtr aes, IntPtr key, uint len);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_AesGcmEncrypt(IntPtr aes, IntPtr output, IntPtr input, uint sz, IntPtr iv, uint ivSz, IntPtr authTag, uint authTagSz, IntPtr authIn, uint authInSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_AesGcmDecrypt(IntPtr aes, IntPtr output, IntPtr input, uint sz, IntPtr iv, uint ivSz, IntPtr authTag, uint authTagSz, IntPtr authIn, uint authInSz);


        /********************************
         * HASH
         */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_HashNew(uint hashType, IntPtr heap, int devId, IntPtr result_code);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_HashDelete(IntPtr hash, IntPtr hash_p);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_HashInit(IntPtr hash, uint hashType);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_HashUpdate(IntPtr hash, uint hashType, IntPtr data, uint dataSz);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_HashFinal(IntPtr hash, uint hashType, IntPtr output);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_HashFree(IntPtr hash, uint hashType);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_HashGetDigestSize(uint hashType);


        /********************************
        * Logging
        */
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static IntPtr wc_GetErrorString(int error);

        public delegate void loggingCb(int lvl, StringBuilder msg);
        private static loggingCb internal_log;

        /// <summary>
        /// Log a message to set logging function
        /// </summary>
        /// <param name="lvl">Level of log message</param>
        /// <param name="msg">Message to log</param>
        private static void log(int lvl, string msg)
        {
            /* if log is not set then print nothing */
            if (internal_log == null)
                return;
            StringBuilder ptr = new StringBuilder(msg);
            internal_log(lvl, ptr);
        }


        /********************************
         * Enum types from wolfSSL library
         */
        /* Logging levels */
        public static readonly int ERROR_LOG = 0;
        public static readonly int INFO_LOG = 1;
        public static readonly int ENTER_LOG = 2;
        public static readonly int LEAVE_LOG = 3;
        public static readonly int OTHER_LOG = 4;
        public static readonly int INVALID_DEVID = -2;
        public static readonly int ECC_MAX_SIG_SIZE = 141;    /* ECC max sig size */
        public static readonly int  ECC_KEY_SIZE = 32;       /* ECC key size */
        public static readonly int MAX_ECIES_TEST_SZ = 200;   /* ECIES max sig size */
        public static readonly int ED25519_SIG_SIZE = 64;     /* ED25519 pub + priv  */
        public static readonly int ED25519_KEY_SIZE = 32;     /* Private key only */
        public static readonly int ED25519_PUB_KEY_SIZE = 32; /* Compressed public */
        public static readonly int AES_128_KEY_SIZE = 16;     /* for 128 bit */
        public static readonly int AES_192_KEY_SIZE = 24;     /* for 192 bit */
        public static readonly int AES_256_KEY_SIZE = 32;     /* for 256 bit */
        public static readonly int AES_BLOCK_SIZE = 16;

        /* Error codes */
        public static readonly int SUCCESS = 0;
        public static readonly int SIG_VERIFY_E = -229;    /* wolfcrypt signature verify error */
        public static readonly int MEMORY_E = -125;        /* Out of memory error */
        public static readonly int EXCEPTION_E = -1;
        public static readonly int BUFFER_E = -131;        /* RSA buffer error, output too small/large */


        /***********************************************************************
         * Class Public Functions
         **********************************************************************/

        /// <summary>
        /// Initialize wolfCrypt library
        /// </summary>
        /// <returns>0 on success</returns>
        public static int Init()
        {
            int ret;
            try
            {
                ret = wolfCrypt_Init();
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "wolfCrypt init error " + e.ToString());
                ret = EXCEPTION_E;
            }
            return ret;
        }

        /// <summary>
        /// Clean up wolfCrypt library memory
        /// </summary>
        /// <returns>0 on success</returns>
        public static int Cleanup()
        {
            int ret;
            try
            {
                ret = wolfCrypt_Cleanup();
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "wolfCrypt cleanup error " + e.ToString());
                ret = EXCEPTION_E;
            }
            return ret;
        }


        /***********************************************************************
         * Random
         **********************************************************************/

        /// <summary>
        /// Create new WC_RNG context
        /// </summary>
        /// <returns>Pointer to allocated WC_RNG or null</returns>
        public static IntPtr RandomNew()
        {
            IntPtr rng;

            try
            {
                /* Allocate and init new WC_RNG structure */
                rng = wc_rng_new(
                    IntPtr.Zero, 0, /* Nonce (optional / used by FIPS only) */
                    IntPtr.Zero);   /* Heap hint for static memory only */
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "random new exception " + e.ToString());
                rng = IntPtr.Zero;
            }

            return rng;
        }

        /// <summary>
        /// Free WC_RNG context
        /// </summary>
        /// <param name="rng">Pointer to allocated WC_RNG</param>
        public static void RandomFree(IntPtr rng)
        {
            if (rng != IntPtr.Zero)
            {
                /* Free WC_RNG structure */
                wc_rng_free(rng);
            }
        }

        /// <summary>
        /// Generate random data (use existing WC_RNG context)
        /// </summary>
        /// <param name="rng">WC_RNG created from RandomNew()</param>
        /// <param name="buf">buffer to populate random data</param>
        /// <param name="sz">size of buffer</param>
        /// <returns>0=success or negative for error</returns>
        public static int Random(IntPtr rng, byte[] buf, int sz)
        {
            int ret;
            IntPtr data;

            try
            {
                /* Allocate global buffer for wolfAPI random */
                data = Marshal.AllocHGlobal(sz);
                if (data != IntPtr.Zero)
                {
                    /* Generate random block */
                    ret = wc_RNG_GenerateBlock(rng, data, Convert.ToUInt32(sz));
                    if (ret == 0)
                    {
                        /* copy returned data */
                        Marshal.Copy(data, buf, 0, sz);
                    }
                    else
                    {
                        log(ERROR_LOG, "random generate block error " + ret + ": " + GetError(ret));
                    }
                    Marshal.FreeHGlobal(data);
                }
                else
                {
                    ret = MEMORY_E;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "random generate block exception " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Generate random data (single shot)
        /// </summary>
        /// <param name="buf">buffer to populate random data</param>
        /// <param name="sz">size of buffer</param>
        /// <returns>0=success or negative for error</returns>
        public static int Random(byte[] buf, int sz)
        {
            int ret;
            IntPtr rng = RandomNew();
            if (rng == IntPtr.Zero)
            {
                return MEMORY_E;
            }
            ret = Random(rng, buf, sz);
            RandomFree(rng);
            return ret;
        }
        /* END Random */


        /***********************************************************************
         * ECC
         **********************************************************************/

        /// <summary>
        /// Generate a new ECC private / public key pair
        /// </summary>
        /// <param name="keysize">Key size in bytes (example: SECP256R1 = 32)</param>
        /// <returns>Allocated ECC key structure or null</returns>
        public static IntPtr EccMakeKey(int keysize, IntPtr rng)
        {
            int ret;
            IntPtr key = IntPtr.Zero;

            try
            {
                /* Allocate and init new WC_RNG structure */
                key = wc_ecc_key_new(IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    ret = wc_ecc_make_key_ex(rng, keysize, key, 0); /* 0=use default curve */
                    if (ret != 0)
                    {
                        EccFreeKey(key);
                        key = IntPtr.Zero;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC make key exception " + e.ToString());

                EccFreeKey(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Sets the ECC rng structure
        /// </summary>
        /// <param name="key">Supplied key as a pointer</param>
        /// <param name="rng">rng context as a pointer</param>
        /// <returns>Returns 0 on success</returns>
        public static int EccSetRng(IntPtr key, IntPtr rng)
        {
            int ret = 0;

            try
            {
                /* Check */
                if (key == IntPtr.Zero)
                {
                    log(ERROR_LOG, "Invalid key or rng pointer.");
                    return MEMORY_E;
                }

                /* Set ECC rng */
                ret = wc_ecc_set_rng(key, rng);
                if (ret != 0)
                {
                    log(ERROR_LOG, "ECC set rng failed returned:" + ret);
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC set rng exception " + e.ToString());
            }

            return ret;
        }

        /// <summary>
        /// Generate a new ECC private / public key pair
        /// </summary>
        /// <param name="keyASN1">ASN.1 private key buffer (see ecc_clikey_der_256)</param>
        /// <returns>Allocated ECC key structure or null</returns>
        public static IntPtr EccImportKey(byte[] keyASN1)
        {
            int ret;
            IntPtr key = IntPtr.Zero;

            try
            {
                key = wc_ecc_key_new(IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    IntPtr idx = Marshal.AllocHGlobal(sizeof(uint));
                    IntPtr keydata = Marshal.AllocHGlobal(keyASN1.Length);
                    Marshal.WriteInt32(idx, 0);
                    Marshal.Copy(keyASN1, 0, keydata, keyASN1.Length);
                    ret = wc_EccPrivateKeyDecode(keydata, idx, key, Convert.ToUInt32(keyASN1.Length));
                    if (ret != 0)
                    {
                        EccFreeKey(key);
                        key = IntPtr.Zero;
                    }
                    Marshal.FreeHGlobal(idx); /* not used */
                    Marshal.FreeHGlobal(keydata);
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC import key exception " + e.ToString());
                EccFreeKey(key); /* make sure its free'd */
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Sign a hash using ECC
        /// </summary>
        /// <param name="key">ECC key structure</param>
        /// <param name="hash">Hash to sign</param>
        /// <param name="signature">Buffer to receive the signature</param>
        /// <returns>Length of the signature on success, otherwise a negative error code</returns>
        public static int EccSign(IntPtr key, byte[] hash, byte[] signature)
        {
            int ret;
            int signedLength = 0;
            IntPtr hashPtr = IntPtr.Zero;
            IntPtr sigPtr = IntPtr.Zero;
            IntPtr sigLen = IntPtr.Zero;
            IntPtr rng = IntPtr.Zero;

            try
            {
                rng = RandomNew();
                hashPtr = Marshal.AllocHGlobal(hash.Length);
                sigPtr = Marshal.AllocHGlobal(signature.Length);
                sigLen = Marshal.AllocHGlobal(sizeof(uint));

                Marshal.WriteInt32(sigLen, signature.Length);
                Marshal.Copy(hash, 0, hashPtr, hash.Length);
                ret = wc_ecc_sign_hash(hashPtr, Convert.ToUInt32(hash.Length), sigPtr, sigLen, rng, key);

                /* Output actual signature length */
                if (ret == 0)
                {
                    signedLength = Marshal.ReadInt32(sigLen);
                    if (signedLength <= signature.Length)
                    {
                        Marshal.Copy(sigPtr, signature, 0, signedLength);
                    }
                    else
                    {
                        ret = BUFFER_E;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC sign exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
                if (sigPtr != IntPtr.Zero) Marshal.FreeHGlobal(sigPtr);
                if (sigLen != IntPtr.Zero) Marshal.FreeHGlobal(sigLen);
                if (rng != IntPtr.Zero) RandomFree(rng);
            }

            return ret == 0 ? signedLength : ret;
        }

        /// <summary>
        /// Verify a signature using ECC
        /// </summary>
        /// <param name="key">ECC key structure</param>
        /// <param name="signature">Signature to verify</param>
        /// <param name="hash">Expected hash value</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int EccVerify(IntPtr key, byte[] signature, byte[] hash)
        {
            int ret;
            IntPtr hashPtr = IntPtr.Zero;
            IntPtr sigPtr = IntPtr.Zero;
            IntPtr res = IntPtr.Zero;

            try
            {
                hashPtr = Marshal.AllocHGlobal(hash.Length);
                sigPtr = Marshal.AllocHGlobal(signature.Length);
                res = Marshal.AllocHGlobal(sizeof(int));

                Marshal.Copy(hash, 0, hashPtr, hash.Length);
                Marshal.Copy(signature, 0, sigPtr, signature.Length);

                ret = wc_ecc_verify_hash(sigPtr, Convert.ToUInt32(signature.Length), hashPtr, Convert.ToUInt32(hash.Length), res, key);

                if (ret == 0)
                {
                    int verifyResult = Marshal.ReadInt32(res);
                    ret = verifyResult == 1 ? 0 : EXCEPTION_E;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC verify exception " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
                if (sigPtr != IntPtr.Zero) Marshal.FreeHGlobal(sigPtr);
                if (res != IntPtr.Zero) Marshal.FreeHGlobal(res);
            }

            return ret;
        }

        /// <summary>
        /// Export ECC Private Key to DER format
        /// </summary>
        /// <param name="key">ECC key structure</param>
        /// <returns>DER-encoded private key as byte array</returns>
        public static int EccExportPrivateKeyToDer(IntPtr key, out byte[] derKey)
        {
            int ret;
            derKey = null;

            try
            {
                int bufferSize = wc_EccPrivateKeyToDer(key, null, 0);
                if (bufferSize < 0) {
                    log(ERROR_LOG, "ECC private key get size failed " + bufferSize.ToString());
                    return bufferSize;
                }
                derKey = new byte[bufferSize];
                ret = wc_EccPrivateKeyToDer(key, derKey, (uint)bufferSize);
                if (ret < 0)
                {
                    log(ERROR_LOG, "ECC private key to der failed " + ret.ToString());
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC export private exception " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Export ECC Public Key to DER format
        /// </summary>
        /// <param name="key">ECC key structure</param>
        /// <param name="includeCurve">Include algorithm curve in the output</param>
        /// <returns>DER-encoded public key as byte array</returns>
        public static int EccExportPublicKeyToDer(IntPtr key, out byte[] derKey, bool includeCurve)
        {
            int ret;
            derKey = null;

            try
            {
                int bufferSize = wc_EccPublicKeyToDer(key, null, 0, includeCurve ? 1 : 0);
                if (bufferSize < 0) {
                    log(ERROR_LOG, "ECC public key get size failed " + bufferSize.ToString());
                    return bufferSize;
                }
                derKey = new byte[bufferSize];
                ret = wc_EccPublicKeyToDer(key, derKey, (uint)bufferSize, includeCurve ? 1 : 0);
                if (ret < 0)
                {
                    log(ERROR_LOG, "ECC public key to der failed " + ret.ToString());
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC export public exception " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Import ECC Public Key from DER format
        /// </summary>
        /// <param name="keyDer">DER-encoded public key</param>
        /// <returns>Allocated ECC key structure or null</returns>
        public static IntPtr EccImportPublicKeyFromDer(byte[] keyDer)
        {
            int ret;
            IntPtr key = IntPtr.Zero;

            try
            {
                key = wc_ecc_key_new(IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    uint idx = 0;
                    ret = wc_EccPublicKeyDecode(keyDer, ref idx, key, (uint)keyDer.Length);
                    if (ret != 0)
                    {
                        EccFreeKey(key);
                        key = IntPtr.Zero;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC import public key exception " + e.ToString());
                EccFreeKey(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Free an ECC key structure
        /// </summary>
        /// <param name="key">ECC key structure allocated using EccMakeKey() or EccImportKey()</param>
        public static void EccFreeKey(IntPtr key)
        {
            if (key != IntPtr.Zero)
            {
                wc_ecc_key_free(key);
            }
        }
        /* END ECC */


        /***********************************************************************
         * ECIES
         **********************************************************************/

        /// <summary>
        /// Create a new ECIES context with flags, RNG, and custom heap.
        /// </summary>
        /// <param name="flags">Flags for the context initialization.</param>
        /// <param name="rng">Random Number Generator (RNG) pointer.</param>
        /// <param name="heap">Custom heap pointer for memory allocations.</param>
        /// <returns>Pointer to the newly created ECIES context or IntPtr.Zero on failure.</returns>
        public static IntPtr EciesNewCtx(int flags, IntPtr rng, IntPtr heap)
        {
            IntPtr ctx = IntPtr.Zero;
            heap = IntPtr.Zero;

            try
            {
                ctx = wc_ecc_ctx_new_ex(flags, rng, heap);
                if (ctx == IntPtr.Zero)
                {
                    log(ERROR_LOG, "ECIES context creation with custom heap failed: returned IntPtr.Zero");
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES context creation with custom heap failed: " + e.ToString());
                return IntPtr.Zero;
            }

            return ctx;
        }

        /// <summary>
        /// Reset the ECIES context with a new RNG.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context to reset.</param>
        /// <param name="rng">New RNG to set.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesCtxReset(IntPtr ctx, IntPtr rng)
        {
            int ret;

            try
            {
                ret = wc_ecc_ctx_reset(ctx, rng);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES context reset exception: " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Set encryption, KDF, and MAC algorithms for the ECIES context.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context.</param>
        /// <param name="encAlgo">Encryption algorithm identifier.</param>
        /// <param name="kdfAlgo">Key Derivation Function (KDF) algorithm identifier.</param>
        /// <param name="macAlgo">MAC algorithm identifier.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesSetAlgo(IntPtr ctx, byte encAlgo, byte kdfAlgo, byte macAlgo)
        {
            int ret;

            try
            {
                ret = wc_ecc_ctx_set_algo(ctx, encAlgo, kdfAlgo, macAlgo);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES set algorithm exception: " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Get the ECIES own salt as a byte array.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context.</param>
        /// <returns>Byte array representing the own salt, or null if there is an error.</returns>
        public static byte[] EciesGetOwnSalt(IntPtr ctx)
        {
            IntPtr saltPtr = IntPtr.Zero;
            byte[] salt = null;

            try
            {
                /* Check ctx */
                if (ctx == IntPtr.Zero)
                {
                    log(ERROR_LOG, "Invalid ECIES context pointer.");
                    return null;
                }

                /* Get own salt */
                saltPtr = wc_ecc_ctx_get_own_salt(ctx);
                if (saltPtr == IntPtr.Zero)
                {
                    log(ERROR_LOG, "Failed to get own salt.");
                    return null;
                }

                /* Allocate salt size and copy to byte array */
                salt = new byte[(int)ecKeySize.EXCHANGE_SALT_SZ];
                Marshal.Copy(saltPtr, salt, 0, (int)ecKeySize.EXCHANGE_SALT_SZ);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES get own salt exception: " + e.ToString());
                return null;
            }
            finally
            {
                /* Cleanup */
                if (saltPtr != IntPtr.Zero) Marshal.FreeHGlobal(saltPtr);
            }

            return salt;
        }

        /// <summary>
        /// Set the peer salt for the ECIES context.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context.</param>
        /// <param name="salt">Peer salt as a byte array.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesSetPeerSalt(IntPtr ctx, byte[] salt)
        {
            IntPtr saltPtr = IntPtr.Zero;
            int ret;

            try
            {
                /* Allocate memory */
                saltPtr = Marshal.AllocHGlobal(salt.Length);
                Marshal.Copy(salt, 0, saltPtr, salt.Length);

                /* Set the peer salt */
                ret = wc_ecc_ctx_set_peer_salt(ctx, saltPtr);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES set peer salt exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (saltPtr != IntPtr.Zero) Marshal.FreeHGlobal(saltPtr);
            }

            return ret;
        }

        /// <summary>
        /// Set the own salt for the ECIES context.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context.</param>
        /// <param name="salt">Own salt as a byte array.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesSetOwnSalt(IntPtr ctx, byte[] salt)
        {
            IntPtr saltPtr = IntPtr.Zero;
            uint saltSz;
            int ret;

            try
            {
                /* Allocate memory */
                saltSz = (uint)salt.Length;
                saltPtr = Marshal.AllocHGlobal(salt.Length);
                Marshal.Copy(salt, 0, saltPtr, salt.Length);

                /* Set the own salt */
                ret = wc_ecc_ctx_set_own_salt(ctx, saltPtr, saltSz);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES set own salt exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (saltPtr != IntPtr.Zero) Marshal.FreeHGlobal(saltPtr);
            }

            return ret;
        }

        /// <summary>
        /// Set the KDF salt for the ECIES context.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context.</param>
        /// <param name="salt">KDF salt as a byte array.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesSetKdfSalt(IntPtr ctx, byte[] salt)
        {
            IntPtr saltPtr = IntPtr.Zero;
            uint saltSz;
            int ret;

            try
            {
                /* Allocate memory */
                saltSz = (uint)salt.Length;
                saltPtr = Marshal.AllocHGlobal(salt.Length);
                Marshal.Copy(salt, 0, saltPtr, salt.Length);

                /* Set the KDF salt */
                ret = wc_ecc_ctx_set_kdf_salt(ctx, saltPtr, saltSz);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES set KDF salt exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (saltPtr != IntPtr.Zero) Marshal.FreeHGlobal(saltPtr);
            }

            return ret;
        }

        /// <summary>
        /// Set the info for the ECIES context.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context.</param>
        /// <param name="info">Info as a byte array.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesSetInfo(IntPtr ctx, byte[] info)
        {
            IntPtr infoPtr = IntPtr.Zero;
            int ret;

            try
            {
                /* Allocate memory */
                infoPtr = Marshal.AllocHGlobal(info.Length);
                Marshal.Copy(info, 0, infoPtr, info.Length);

                /* Set the info */
                ret = wc_ecc_ctx_set_info(ctx, infoPtr, info.Length);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES set info exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (infoPtr != IntPtr.Zero) Marshal.FreeHGlobal(infoPtr);
            }

            return ret;
        }

        /// <summary>
        /// Encrypt a message using ECIES.
        /// </summary>
        /// <param name="privKey">Private key.</param>
        /// <param name="pubKey">Public key.</param>
        /// <param name="msg">Message to encrypt.</param>
        /// <param name="msgSz">Message size.</param>
        /// <param name="outBuffer">Output buffer.</param>
        /// <param name="ctx">ECIES context.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesEncrypt(IntPtr privKey, IntPtr pubKey, byte[] msg, uint msgSz, byte[] outBuffer, IntPtr ctx)
        {
            int ret;
            int outBufferLength = 0;
            IntPtr msgPtr = IntPtr.Zero;
            IntPtr outBufferPtr = IntPtr.Zero;
            IntPtr outSz = IntPtr.Zero;

            try
            {
                /* Allocate memory */
                msgPtr = Marshal.AllocHGlobal(msg.Length);
                outBufferPtr = Marshal.AllocHGlobal(outBuffer.Length);
                outSz = Marshal.AllocHGlobal(sizeof(uint));

                Marshal.WriteInt32(outSz, outBuffer.Length);
                Marshal.Copy(msg, 0, msgPtr, msg.Length);

                /* Encrypt */
                ret = wc_ecc_encrypt(privKey, pubKey, msgPtr, msgSz, outBufferPtr, outSz, ctx);
                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to encrypt message using ECIES. Error code: " + ret);
                }
                /* Output actual output buffer length */
                if (ret == 0)
                {
                    outBufferLength = Marshal.ReadInt32(outSz);
                    if (outBufferLength <= outBuffer.Length)
                    {
                        Marshal.Copy(outBufferPtr, outBuffer, 0, outBufferLength);
                    }
                    else
                    {
                        ret = BUFFER_E;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES encryption exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (msgPtr != IntPtr.Zero) Marshal.FreeHGlobal(msgPtr);
                if (outBufferPtr != IntPtr.Zero) Marshal.FreeHGlobal(outBufferPtr);
                if (outSz != IntPtr.Zero) Marshal.FreeHGlobal(outSz);
            }

            return ret == 0 ? outBufferLength : ret;
        }

        /// <summary>
        /// Decrypt a message using ECIES.
        /// </summary>
        /// <param name="privKey">Private key.</param>
        /// <param name="pubKey">Public key.</param>
        /// <param name="msg">Encrypted message.</param>
        /// <param name="msgSz">Message size.</param>
        /// <param name="outBuffer">Output buffer for the decrypted message.</param>
        /// <param name="ctx">ECIES context.</param>
        /// <returns>0 on success, or a negative error code on failure.</returns>
        public static int EciesDecrypt(IntPtr privKey, IntPtr pubKey, byte[] msg, uint msgSz, byte[] outBuffer, IntPtr ctx)
        {
            int ret;
            int outBufferLength = 0;
            IntPtr msgPtr = IntPtr.Zero;
            IntPtr outBufferPtr = IntPtr.Zero;
            IntPtr outSz = IntPtr.Zero;

            try
            {
                /* Allocate memory */
                msgPtr = Marshal.AllocHGlobal(msg.Length);
                outBufferPtr = Marshal.AllocHGlobal(outBuffer.Length);
                outSz = Marshal.AllocHGlobal(sizeof(uint));

                Marshal.WriteInt32(outSz, outBuffer.Length);
                Marshal.Copy(msg, 0, msgPtr, msg.Length);

                /* Decrypt */
                ret = wc_ecc_decrypt(privKey, pubKey, msgPtr, msgSz, outBufferPtr, outSz, ctx);
                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to decrypt message using ECIES. Error code: " + ret);
                }
                /* Output actual output buffer length */
                if (ret == 0)
                {
                    outBufferLength = Marshal.ReadInt32(outSz);
                    if (outBufferLength <= outBuffer.Length)
                    {
                        Marshal.Copy(outBufferPtr, outBuffer, 0, outBufferLength);
                    }
                    else
                    {
                        ret = BUFFER_E;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECIES decryption exception: " + e.ToString());
                return EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (msgPtr != IntPtr.Zero) Marshal.FreeHGlobal(msgPtr);
                if (outBufferPtr != IntPtr.Zero) Marshal.FreeHGlobal(outBufferPtr);
                if (outSz != IntPtr.Zero) Marshal.FreeHGlobal(outSz);
            }

            return ret == 0 ? outBufferLength : ret;
        }

        /// <summary>
        /// Free the ECIES context.
        /// </summary>
        /// <param name="ctx">Pointer to the ECIES context to free.</param>
        public static void EciesFreeCtx(IntPtr ctx)
        {
            if (ctx != IntPtr.Zero)
            {
                wc_ecc_ctx_free(ctx);
            }
        }

        /********************************
         * ENUMS
         */
        public enum ecEncAlgo {
            ecAES_128_CBC = 1,  /* default */
            ecAES_256_CBC = 2,
            ecAES_128_CTR = 3,
            ecAES_256_CTR = 4
        }

        public enum ecKdfAlgo {
            ecHKDF_SHA256      = 1,  /* default */
            ecHKDF_SHA1        = 2,
            ecKDF_X963_SHA1    = 3,
            ecKDF_X963_SHA256  = 4,
            ecKDF_SHA1         = 5,
            ecKDF_SHA256       = 6
        }

        public enum ecMacAlgo {
            ecHMAC_SHA256 = 1,  /* default */
            ecHMAC_SHA1   = 2
        }

        public enum ecKeySize {
            KEY_SIZE_128     = 16,
            KEY_SIZE_256     = 32,
            IV_SIZE_64       =  8,
            IV_SIZE_128      = 16,
            ECC_MAX_IV_SIZE  = 16,
            EXCHANGE_SALT_SZ = 16,
            EXCHANGE_INFO_SZ = 23
        }

        public enum ecFlags {
            REQ_RESP_CLIENT = 1,
            REQ_RESP_SERVER = 2
        }
        /* END ECIES */


        /***********************************************************************
         * ECDHE
         **********************************************************************/

        /// <summary>
        /// Generate a shared secret using ECC
        /// </summary>
        /// <param name="privateKey">ECC private key</param>
        /// <param name="publicKey">ECC public key</param>
        /// <param name="secret">Buffer to receive the shared secret</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int EcdheSharedSecret(IntPtr privateKey, IntPtr publicKey, byte[] secret, IntPtr rng)
        {
            int ret;
            int secretLength = secret.Length;

            try
            {
                /* set RNG for Public Key */
                ret = EccSetRng(privateKey, rng);
                if (ret != 0)
                {
                    throw new Exception("Failed to set Public Key RNG Error code: " + ret);
                }

                /* set RNG for Private Key */
                ret = EccSetRng(publicKey, rng);
                if (ret != 0)
                {
                    throw new Exception("Failed to set Private Key RNG. Error code: " + ret);
                }

                /* Generate shared secret */
                if (privateKey != IntPtr.Zero || publicKey != IntPtr.Zero)
                {
                    ret = wc_ecc_shared_secret(privateKey, publicKey, secret, ref secretLength);
                    if (ret != 0)
                    {
                        throw new Exception("Failed to compute ECC shared secret. Error code: " + ret);
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ECC shared secret exception " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }
        /* END ECDHE */


        /***********************************************************************
         * RSA
         **********************************************************************/

        /// <summary>
        /// Generate a new RSA private/public key pair
        /// </summary>
        /// <param name="heap">Pointer to the heap for memory allocation
        /// (use IntPtr.Zero if not applicable)</param>
        /// <param name="devId">Device ID (if applicable, otherwise use 0)</param>
        /// <param name="keysize">Key size in bits (example: 2048)</param>
        /// <param name="exponent">Exponent for RSA key generation (default is 65537)</param>
        /// <returns>Allocated RSA key structure or null on failure</returns>
        public static IntPtr RsaMakeKey(IntPtr heap, int devId, int keysize, Int32 exponent)
        {
            int ret;
            IntPtr key = IntPtr.Zero;
            IntPtr rng = IntPtr.Zero;

            try
            {
                /* Allocate and init new RSA key structure */
                key = wc_NewRsaKey(heap, devId, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    rng = RandomNew();
                    if (rng == IntPtr.Zero)
                    {
                        throw new Exception("Failed to create rng.");
                    }

                    ret = wc_MakeRsaKey(key, keysize, exponent, rng);
                    if (ret != 0)
                    {
                        RsaFreeKey(key);
                        key = IntPtr.Zero;
                    }

                    RandomFree(rng);
                    rng = IntPtr.Zero;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "RSA make key exception " + e.ToString());
                if (rng != IntPtr.Zero) RandomFree(rng);
                if (key != IntPtr.Zero) RsaFreeKey(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        public static IntPtr RsaMakeKey(IntPtr heap, int devId, int keysize)
        {
            return RsaMakeKey(heap, devId, keysize, 65537);
        }

        /// <summary>
        /// Import an RSA private key from ASN.1 buffer
        /// </summary>
        /// <param name="keyASN1">ASN.1 private key buffer</param>
        /// <returns>Allocated RSA key structure or null</returns>
        public static IntPtr RsaImportKey(byte[] keyASN1)
        {
            int ret;
            IntPtr key = IntPtr.Zero;

            try
            {
                key = wc_NewRsaKey(IntPtr.Zero, INVALID_DEVID, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    IntPtr idx = Marshal.AllocHGlobal(sizeof(uint));
                    IntPtr keydata = Marshal.AllocHGlobal(keyASN1.Length);
                    Marshal.WriteInt32(idx, 0);
                    Marshal.Copy(keyASN1, 0, keydata, keyASN1.Length);
                    ret = wc_RsaPrivateKeyDecode(keydata, idx, key, Convert.ToUInt32(keyASN1.Length));
                    if (ret != 0)
                    {
                        RsaFreeKey(key);
                        key = IntPtr.Zero;
                    }
                    Marshal.FreeHGlobal(idx); /* not used */
                    Marshal.FreeHGlobal(keydata);
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "RSA make key exception " + e.ToString());
                RsaFreeKey(key); /* make sure its free'd */
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Sign a hash using RSA and SSL-style padding
        /// </summary>
        /// <param name="key">RSA key structure</param>
        /// <param name="hash">Hash to sign</param>
        /// <param name="signature">Buffer to receive the signature</param>
        /// <returns>Length of the signature on success, otherwise an error code</returns>
        public static int RsaSignSSL(IntPtr key, byte[] hash, byte[] signature)
        {
            IntPtr hashPtr = Marshal.AllocHGlobal(hash.Length);
            IntPtr sigPtr = Marshal.AllocHGlobal(signature.Length);
            IntPtr rng = IntPtr.Zero;
            int ret;

            try
            {
                rng = RandomNew();
                if (rng == IntPtr.Zero)
                {
                    throw new Exception("Failed to create RNG.");
                }

                Marshal.Copy(hash, 0, hashPtr, hash.Length);

                ret = wc_RsaSSL_Sign(hashPtr, hash.Length, sigPtr, signature.Length, key, rng);
                if (ret >= 0) /* `wc_RsaSSL_Sign` returns the signature length on success */
                {
                    Marshal.Copy(sigPtr, signature, 0, ret);
                }
            }
            finally
            {
                if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
                if (sigPtr != IntPtr.Zero) Marshal.FreeHGlobal(sigPtr);
                if (rng != IntPtr.Zero) RandomFree(rng);
            }

            return ret;
        }

        /// <summary>
        /// Verify a signature using RSA and SSL-style padding
        /// </summary>
        /// <param name="key">RSA key structure</param>
        /// <param name="signature">Signature to verify</param>
        /// <param name="hash">Expected hash value</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int RsaVerifySSL(IntPtr key, byte[] signature, byte[] hash)
        {
            IntPtr hashPtr = IntPtr.Zero;
            IntPtr sigPtr = IntPtr.Zero;
            int ret;

            try
            {
                hashPtr = Marshal.AllocHGlobal(hash.Length);
                sigPtr = Marshal.AllocHGlobal(signature.Length);

                Marshal.Copy(signature, 0, sigPtr, signature.Length);

                ret = wc_RsaSSL_Verify(sigPtr, signature.Length, hashPtr, hash.Length, key);

                if (ret == hash.Length)
                {
                    byte[] verifiedHash = new byte[hash.Length];
                    Marshal.Copy(hashPtr, verifiedHash, 0, hash.Length);

                    if (ByteArrayVerify(verifiedHash, hash))
                    {
                        ret = 0;
                    }
                    else
                    {
                        ret = SIG_VERIFY_E;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "RSA verify exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
                if (sigPtr != IntPtr.Zero) Marshal.FreeHGlobal(sigPtr);
            }

            return ret;
        }

        /// <summary>
        /// Encrypt data using RSA public key encryption
        /// </summary>
        /// <param name="key">RSA key structure</param>
        /// <param name="input">Data to encrypt</param>
        /// <param name="output">Buffer to receive the encrypted data</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int RsaPublicEncrypt(IntPtr key, byte[] input, byte[] output)
        {
            IntPtr inPtr = Marshal.AllocHGlobal(input.Length);
            IntPtr outPtr = Marshal.AllocHGlobal(output.Length);
            Marshal.Copy(input, 0, inPtr, input.Length);

            int ret = wc_RsaPublicEncrypt(inPtr, input.Length, outPtr, output.Length, key);

            if (ret > 0)
            {
                Marshal.Copy(outPtr, output, 0, ret);
            }

            Marshal.FreeHGlobal(inPtr);
            Marshal.FreeHGlobal(outPtr);

            return ret > 0 ? 0 : ret;
        }

        /// <summary>
        /// Decrypt data using RSA private key decryption
        /// </summary>
        /// <param name="key">RSA key structure</param>
        /// <param name="input">Encrypted data</param>
        /// <param name="output">Buffer to receive the decrypted data</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int RsaPrivateDecrypt(IntPtr key, byte[] input, byte[] output)
        {
            IntPtr inPtr = Marshal.AllocHGlobal(input.Length);
            IntPtr outPtr = Marshal.AllocHGlobal(output.Length);
            Marshal.Copy(input, 0, inPtr, input.Length);

            int ret = wc_RsaPrivateDecrypt(inPtr, input.Length, outPtr, output.Length, key);

            if (ret > 0)
            {
                Marshal.Copy(outPtr, output, 0, ret);
            }

            Marshal.FreeHGlobal(inPtr);
            Marshal.FreeHGlobal(outPtr);

            return ret > 0 ? 0 : ret;
        }

        /// <summary>
        /// Free an RSA key structure
        /// </summary>
        /// <param name="key">RSA key structure allocated using RsaMakeKey() or RsaImportKey()</param>
        public static void RsaFreeKey(IntPtr key)
        {
            if (key != IntPtr.Zero)
            {
                wc_DeleteRsaKey(key, IntPtr.Zero);
                key = IntPtr.Zero;
            }
        }
        /* END RSA */


        /***********************************************************************
         * ED25519
         **********************************************************************/

        /// <summary>
        /// Generate a new ED25519 key pair with a specified heap, device ID, and internally managed RNG.
        /// </summary>
        /// <param name="heap">Heap to use for memory allocations (can be IntPtr.Zero).</param>
        /// <param name="devId">Device ID for hardware-based keys (can be 0 for software).</param>
        /// <returns>0 on success, or an error code on failure.</returns>
        public static IntPtr Ed25519MakeKey(IntPtr heap, int devId)
        {
            int ret = 0;
            IntPtr rng = IntPtr.Zero;
            IntPtr key = IntPtr.Zero;

            try
            {
                rng = RandomNew();
                if (rng == IntPtr.Zero)
                {
                    throw new Exception("Failed to create RNG.");
                }

                key = wc_ed25519_new(heap, devId, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    ret = wc_ed25519_make_key(rng, 32, key);
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ED25519 make key exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (rng != IntPtr.Zero) RandomFree(rng);
                if (ret != 0)
                {
                    wc_ed25519_delete(key, IntPtr.Zero);
                    key = IntPtr.Zero;
                }
            }

            return key;
        }

        /// <summary>
        /// Sign a message with an ED25519 private key.
        /// </summary>
        /// <param name="inMsg">Message to be signed</param>
        /// <param name="outMsg">Buffer to receive the signature</param>
        /// <param name="key">Private key used for signing</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int Ed25519SignMsg(byte[] inMsg, out byte[] outMsg, IntPtr key)
        {
            int ret;
            IntPtr inMsgPtr = Marshal.AllocHGlobal(inMsg.Length);
            IntPtr outMsgPtr = Marshal.AllocHGlobal(ED25519_SIG_SIZE);
            outMsg = null;

            try
            {
                Marshal.Copy(inMsg, 0, inMsgPtr, inMsg.Length);
                uint outMsgSize = (uint)ED25519_SIG_SIZE;
                ret = wc_ed25519_sign_msg(inMsgPtr, (uint)inMsg.Length, outMsgPtr, ref outMsgSize, key);
                if (ret == 0)
                {
                    outMsg = new byte[outMsgSize];
                    Marshal.Copy(outMsgPtr, outMsg, 0, (int)outMsgSize);
                }
            }
            finally
            {
                /* Cleanup */
                if (inMsgPtr != IntPtr.Zero) Marshal.FreeHGlobal(inMsgPtr);
                if (outMsgPtr != IntPtr.Zero) Marshal.FreeHGlobal(outMsgPtr);
            }

            return ret;
        }

        /// <summary>
        /// Verify a signature of a message with an ED25519 public key.
        /// </summary>
        /// <param name="sig">Signature to verify</param>
        /// <param name="msg">Message that was signed</param>
        /// <param name="key">Public key used for verification</param>
        /// <returns>0 if the verification succeeds, otherwise an error code</returns>
        public static int Ed25519VerifyMsg(byte[] sig, byte[] msg, IntPtr key)
        {
            IntPtr sigPtr = IntPtr.Zero;
            IntPtr msgPtr = IntPtr.Zero;
            int ret = 0;

            try
            {
                /* Allocate memory */
                sigPtr = Marshal.AllocHGlobal(sig.Length);
                msgPtr = Marshal.AllocHGlobal(msg.Length);

                Marshal.Copy(sig, 0, sigPtr, sig.Length);
                Marshal.Copy(msg, 0, msgPtr, msg.Length);

                int verify = 0;
                ret = wc_ed25519_verify_msg(sigPtr, (uint)sig.Length, msgPtr, (uint)msg.Length, ref verify, key);

                if (ret == 0 && verify == 1)
                {
                    ret = 0;
                }
                else
                {
                    ret = SIG_VERIFY_E;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ED25519 verify exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (sigPtr != IntPtr.Zero) Marshal.FreeHGlobal(sigPtr);
                if (msgPtr != IntPtr.Zero) Marshal.FreeHGlobal(msgPtr);
            }

            return ret;
        }

        /// <summary>
        /// Decode an ED25519 private key from DER format.
        /// </summary>
        /// <param name="input">DER-encoded private key as byte array.</param>
        /// <returns>Allocated ED25519 key structure or IntPtr.Zero on failure.</returns>
        public static IntPtr Ed25519PrivateKeyDecode(byte[] input)
        {
            IntPtr key = IntPtr.Zero;
            uint idx = 0;
            int ret;

            try
            {
                key = wc_ed25519_new(IntPtr.Zero, INVALID_DEVID, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    ret = wc_Ed25519PrivateKeyDecode(input, ref idx, key, (uint)input.Length);
                    if (ret != 0)
                    {
                        Ed25519FreeKey(key);
                        key = IntPtr.Zero;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ED25519 private key decode exception: " + e.ToString());
                if (key != IntPtr.Zero) Ed25519FreeKey(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Decode an ED25519 public key from DER format.
        /// </summary>
        /// <param name="input">DER-encoded public key as byte array.</param>
        /// <returns>Allocated ED25519 key structure or IntPtr.Zero on failure.</returns>
        public static IntPtr Ed25519PublicKeyDecode(byte[] input)
        {
            IntPtr key = IntPtr.Zero;
            uint idx = 0;
            int ret;

            try
            {
                key = wc_ed25519_new(IntPtr.Zero, INVALID_DEVID, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    ret = wc_Ed25519PublicKeyDecode(input, ref idx, key, (uint)input.Length);
                    if (ret != 0)
                    {
                        Ed25519FreeKey(key);
                        key = IntPtr.Zero;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ED25519 public key decode exception: " + e.ToString());
                if (key != IntPtr.Zero) Ed25519FreeKey(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Export an ED25519 key to DER format.
        /// </summary>
        /// <param name="key">ED25519 key structure.</param>
        /// <param name="privKey">DER-encoded public key as byte array.</param>
        /// <returns>DER-encoded key as byte array.</returns>
        public static int Ed25519ExportKeyToDer(IntPtr key, out byte[] privKey)
        {
            int ret;
            privKey = null;

            try
            {
                /* Get length */
                int len = wc_Ed25519KeyToDer(key, null, 0);
                if (len < 0)
                {
                    log(ERROR_LOG, "Failed to determine length. Error code: " + len);
                    return len;
                }

                privKey = new byte[len];
                ret = wc_Ed25519KeyToDer(key, privKey, (uint)privKey.Length);

                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to export ED25519 private key to DER format. Error code: " + ret);
                    return ret;
                }
            }
            catch(Exception e)
            {
                log(ERROR_LOG, "ED25519 export private key to DER exception: " + e.ToString());
                return EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Export an ED25519 private key to DER format.
        /// </summary>
        /// <param name="key">ED25519 private key structure.</param>
        /// <param name="derKey">DER-encoded private key as byte array.</param>
        /// <returns>DER-encoded private key as byte array.</returns>
        public static int Ed25519ExportPrivateKeyToDer(IntPtr key, out byte[] derKey)
        {
            int ret;
            derKey = null;

            try
            {
                /* Determine length */
                int len = wc_Ed25519PrivateKeyToDer(key, null, 0);
                if (len < 0)
                {
                    log(ERROR_LOG, "Failed to determine length. Error code: " + len);
                    return len;
                }

                derKey = new byte[len];
                ret = wc_Ed25519PrivateKeyToDer(key, derKey, (uint)derKey.Length);

                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to export ED25519 private key to DER format. Error code: " + ret);
                    return ret;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ED25519 export private key to DER exception: " + e.ToString());
                return EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Export an ED25519 public key to DER format.
        /// </summary>
        /// <param name="key">ED25519 public key structure.</param>
        /// <param name="includeAlg">Whether to include the algorithm identifier in the output.</param>
        /// <param name="pubKey">DER-encoded public key as byte array.</param>
        /// <returns>An error code indicating success (0) or failure (negative value).</returns>
        public static int Ed25519ExportPublicKeyToDer(IntPtr key, out byte[] pubKey, bool includeAlg)
        {
            int ret;
            pubKey = null;

            try
            {
                /* Determine length */
                int len = wc_Ed25519PublicKeyToDer(key, null, 0, 1);
                if (len < 0)
                {
                    log(ERROR_LOG, "Failed to determine length. Error code: " + len);
                    return len;
                }

                pubKey = new byte[len];
                ret = wc_Ed25519PublicKeyToDer(key, pubKey, (uint)pubKey.Length, includeAlg ? 1 : 0);
                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to export ED25519 public key to DER format. Error code: " + ret);
                    return ret;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "ED25519 export public key to DER exception: " + e.ToString());
                return EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Free an ED25519 key.
        /// </summary>
        /// <param name="key">Key to be freed</param>
        public static void Ed25519FreeKey(IntPtr key)
        {
            wc_ed25519_delete(key, IntPtr.Zero);
            key = IntPtr.Zero;
        }
        /* END ED25519 */


        /***********************************************************************
         * RAW ED25519
         **********************************************************************/

        /// <summary>
    	/// Initialize an ED25519 key.
    	/// </summary>
    	/// <param name="key">Buffer to receive the initialized key</param>
    	/// <returns>0 on success, otherwise an error code</returns>
    	public static int Ed25519InitKey(out IntPtr key)
        {
            key = IntPtr.Zero;
            try
            {
                key = Marshal.AllocHGlobal(ED25519_SIG_SIZE);
                int ret = wc_ed25519_init(key);

                if (ret != 0)
                {
                    Marshal.FreeHGlobal(key);
                    key = IntPtr.Zero;
                }

                return ret;
            }
            catch
            {
                /* Cleanup */
                Marshal.FreeHGlobal(key);
                key = IntPtr.Zero;
                throw;
            }
        }

        /// <summary>
        /// Import a public key into an ED25519 key structure.
        /// </summary>
        /// <param name="inMsg">Public key to import</param>
        /// <param name="inLen">Length of the public key</param>
        /// <param name="key">Buffer to receive the imported key</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int Ed25519ImportPublic(byte[] inMsg, uint inLen, out IntPtr key)
        {
            int ret;
            key = IntPtr.Zero;
            IntPtr inMsgPtr = IntPtr.Zero;

            try
            {
                /* Allocate memory */
                key = Marshal.AllocHGlobal(ED25519_PUB_KEY_SIZE);
                if (key == IntPtr.Zero)
                {
                    throw new OutOfMemoryException("Failed to allocate memory for the key.");
                }

                inMsgPtr = Marshal.AllocHGlobal(inMsg.Length);
                if (inMsgPtr == IntPtr.Zero)
                {
                    throw new OutOfMemoryException("Failed to allocate memory for the input message.");
                }
                Marshal.Copy(inMsg, 0, inMsgPtr, inMsg.Length);

                ret = wc_ed25519_import_public(inMsgPtr, inLen, key);
                if (ret != 0)
                {
                    return ret;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in EdImportPublic: {ex.Message}");

                return EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (inMsgPtr != IntPtr.Zero) Marshal.FreeHGlobal(inMsgPtr);
                if (key != IntPtr.Zero) Marshal.FreeHGlobal(key);
            }

            return ret;
        }

        /// <summary>
        /// Export a public key from an ED25519 key structure.
        /// </summary>
        /// <param name="key">ED25519 key structure</param>
        /// <param name="outMsg">Buffer to receive the exported public key</param>
        /// <param name="outLen">Length of the exported public key</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int Ed25519ExportPublic(IntPtr key, byte[] outMsg, out uint outLen)
        {
            int ret;
            IntPtr outMsgPtr = IntPtr.Zero;

            try
            {
                outMsgPtr = Marshal.AllocHGlobal(outMsg.Length);
                outLen = (uint)outMsg.Length;
                ret = wc_ed25519_export_public(key, outMsgPtr, ref outLen);
                if (ret == 0)
                {
                    Marshal.Copy(outMsgPtr, outMsg, 0, (int)outLen);
                }
                else
                {
                    outLen = 0;
                }
            }
            finally
            {
                /* Cleanup */
                if (outMsgPtr != IntPtr.Zero) Marshal.FreeHGlobal(outMsgPtr);
            }

            return ret;
        }

        /// <summary>
        /// Export a private key from an ED25519 key structure.
        /// </summary>
        /// <param name="key">ED25519 key structure</param>
        /// <param name="outMsg">Buffer to receive the exported private key</param>
        /// <param name="outLen">Length of the exported private key</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int Ed25519ExportPrivate(IntPtr key, byte[] outMsg, out uint outLen)
        {
            int ret;
            IntPtr outMsgPtr = IntPtr.Zero;

            try
            {
                outMsgPtr = Marshal.AllocHGlobal(outMsg.Length);
                outLen = (uint)outMsg.Length;
                ret = wc_ed25519_export_private(key, outMsgPtr, ref outLen);
                if (ret == 0)
                {
                    Marshal.Copy(outMsgPtr, outMsg, 0, (int)outLen);
                }
                else
                {
                    outLen = 0;
                }
            }
            finally
            {
                /* Cleanup */
                if (outMsgPtr != IntPtr.Zero) Marshal.FreeHGlobal(outMsgPtr);
            }

            return ret;
        }

        /// <summary>
        /// Generate a public key from a private key.
        /// </summary>
        /// <param name="key">The private key used to generate the public key</param>
        /// <param name="pubKey">Buffer to receive the public key</param>
        /// <param name="pubKeySz">Size of the public key buffer</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int Ed25519MakePublic(IntPtr key, byte[] pubKey, out uint pubKeySz)
        {
            int ret;
            IntPtr pubKeyPtr = Marshal.AllocHGlobal(pubKey.Length);

            try
            {
                pubKeySz = (uint)pubKey.Length;
                ret = wc_ed25519_make_public(key, pubKeyPtr, pubKeySz);
                if (ret == 0)
                {
                    Marshal.Copy(pubKeyPtr, pubKey, 0, (int)pubKeySz);
                }
            }
            finally
            {
                /* Cleanup */
                if (pubKeyPtr != IntPtr.Zero) Marshal.FreeHGlobal(pubKeyPtr);
            }

            return ret;
        }

        /// <summary>
        /// Get the size of the ED25519 key.
        /// </summary>
        /// <param name="key">ED25519 key structure</param>
        /// <returns>Size of the key, or an error code if failed</returns>
        public static int Ed25519GetKeySize(IntPtr key)
        {
            return wc_ed25519_size(key);
        }
        /* END RAW ED25519 */


        /***********************************************************************
         * Curve25519
         **********************************************************************/

        /// <summary>
        /// Generate a new Curve25519 key pair with a specified heap, device ID, and internally managed RNG.
        /// </summary>
        /// <param name="heap">Heap to use for memory allocations (can be IntPtr.Zero).</param>
        /// <param name="devId">Device ID for hardware-based keys (can be 0 for software).</param>
        /// <returns>0 on success, or an error code on failure.</returns>
        public static IntPtr Curve25519MakeKey(IntPtr heap, int devId)
        {
            int ret = 0;
            IntPtr rng = IntPtr.Zero;
            IntPtr key = IntPtr.Zero;

            try
            {
                rng = RandomNew();
                if (rng == IntPtr.Zero)
                {
                    throw new Exception("Failed to create RNG.");
                }

                key = wc_curve25519_new(heap, devId, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    ret = wc_curve25519_make_key(rng, 32, key);
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Curve25519 make key exception: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (rng != IntPtr.Zero) RandomFree(rng);
                if (ret != 0)
                {
                    wc_curve25519_delete(key, IntPtr.Zero);
                    key = IntPtr.Zero;
                }
            }

            return key;
        }

        /// <summary>
        /// Decode an Curve25519 private key from DER format.
        /// </summary>
        /// <param name="input">DER-encoded private key as byte array.</param>
        /// <returns>Allocated Curve25519 key structure or IntPtr.Zero on failure.</returns>
        public static IntPtr Curve25519PrivateKeyDecode(byte[] input)
        {
            IntPtr key = IntPtr.Zero;
            uint idx = 0;
            int ret;

            try
            {
                key = wc_ed25519_new(IntPtr.Zero, INVALID_DEVID, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    ret = wc_Ed25519PrivateKeyDecode(input, ref idx, key, (uint)input.Length);
                    if (ret != 0)
                    {
                        Curve25519FreeKey(key);
                        key = IntPtr.Zero;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Curve25519 private key decode exception: " + e.ToString());
                if (key != IntPtr.Zero) Curve25519FreeKey(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Decode an Curve25519 public key from DER format.
        /// </summary>
        /// <param name="input">DER-encoded public key as byte array.</param>
        /// <returns>Allocated Curve25519 key structure or IntPtr.Zero on failure.</returns>
        public static IntPtr Curve25519PublicKeyDecode(byte[] input)
        {
            IntPtr key = IntPtr.Zero;
            uint idx = 0;
            int ret;

            try
            {
                key = wc_curve25519_new(IntPtr.Zero, INVALID_DEVID, IntPtr.Zero);
                if (key != IntPtr.Zero)
                {
                    ret = wc_Curve25519PublicKeyDecode(input, ref idx, key, (uint)input.Length);
                    if (ret != 0)
                    {
                        Curve25519FreeKey(key);
                        key = IntPtr.Zero;
                    }
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Curve25519 public key decode exception: " + e.ToString());
                if (key != IntPtr.Zero) Curve25519FreeKey(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Export an Curve25519 key to DER format.
        /// </summary>
        /// <param name="key">Curve25519 key structure.</param>
        /// <param name="derKey">DER-encoded public key as byte array.</param>
        /// <returns>DER-encoded key as byte array.</returns>
        public static int Curve25519ExportPrivateKeyToDer(IntPtr key, out byte[] derKey)
        {
            int ret;
            derKey = null;

            try
            {
                /* Determine length */
                int len = wc_Curve25519PrivateKeyToDer(key, null, 0);
                if (len < 0)
                {
                    log(ERROR_LOG, "Failed to determine length. Error code: " + len);
                    return len;
                }

                derKey = new byte[len];
                ret = wc_Curve25519PrivateKeyToDer(key, derKey, (uint)derKey.Length);

                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to export Curve25519 private key to DER format. Error code: " + ret);
                    return ret;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "CURVE25519 export private key to DER exception: " + e.ToString());
                return EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Export an Curve25519 public key to DER format.
        /// </summary>
        /// <param name="key">Curve25519 public key structure.</param>
        /// <param name="includeAlg">Whether to include the algorithm identifier in the output.</param>
        /// <param name="derKey">DER-encoded public key as byte array.</param>
        /// <returns>An error code indicating success (0) or failure (negative value).</returns>
        public static int Curve25519ExportPublicKeyToDer(IntPtr key, out byte[] derKey, bool includeAlg)
        {
            int ret;
            derKey = null;

            try
            {
                /* Determine length */
                int len = wc_Curve25519PublicKeyToDer(key, null, 0, 1);
                if (len < 0)
                {
                    log(ERROR_LOG, "Failed to determine length. Error code: " + len);
                    return len;
                }

                derKey = new byte[len];
                ret = wc_Curve25519PublicKeyToDer(key, derKey, (uint)derKey.Length, includeAlg ? 1 : 0);
                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to export Curve25519 public key to DER format. Error code: " + ret);
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Curve25519 export public key to DER exception: " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Free an Curve25519 key.
        /// </summary>
        /// <param name="key">Key to be freed</param>
        public static void Curve25519FreeKey(IntPtr key)
        {
            wc_curve25519_delete(key, IntPtr.Zero);
            key = IntPtr.Zero;
        }
        /* END Curve25519 */


        /***********************************************************************
         * RAW Curve25519
         **********************************************************************/

        /// <summary>
        /// Generate a shared secret using Curve25519
        /// </summary>
        /// <param name="privateKey">Curve25519 private key</param>
        /// <param name="publicKey">Curve25519 public key</param>
        /// <param name="secret">Buffer to receive the shared secret</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int Curve25519SharedSecret(IntPtr privateKey, IntPtr publicKey, byte[] secret)
        {
            int ret;
            int secretLength = secret.Length;

            try
            {
                ret = wc_curve25519_shared_secret(privateKey, publicKey, secret, ref secretLength);
                if (ret != 0)
                {
                    throw new Exception("Failed to compute Curve25519 shared secret. Error code: " + ret);
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Curve25519 shared secret exception " + e.ToString());
                ret = EXCEPTION_E;
            }

            return ret;
        }

        /// <summary>
        /// Import a Curve25519 private key from a byte array
        /// </summary>
        /// <param name="privateKey">Private key byte array</param>
        /// <returns>Allocated Curve25519 key structure or null</returns>
        public static IntPtr Curve25519ImportPrivateKey(byte[] privateKey)
        {
            IntPtr key = IntPtr.Zero;

            try
            {
                key = Marshal.AllocHGlobal(privateKey.Length);
                Marshal.Copy(privateKey, 0, key, privateKey.Length);
                int ret = wc_curve25519_import_private(key, privateKey.Length, key);
                if (ret != 0)
                {
                    Marshal.FreeHGlobal(key);
                    key = IntPtr.Zero;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Curve25519 import private key exception " + e.ToString());
                if (key != IntPtr.Zero) Marshal.FreeHGlobal(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Import a Curve25519 public key from a byte array
        /// </summary>
        /// <param name="publicKey">Public key byte array</param>
        /// <returns>Allocated Curve25519 key structure or null</returns>
        public static IntPtr Curve25519ImportPublicKey(byte[] publicKey)
        {
            IntPtr key = IntPtr.Zero;

            try
            {
                key = Marshal.AllocHGlobal(publicKey.Length);
                Marshal.Copy(publicKey, 0, key, publicKey.Length);
                int ret = wc_curve25519_import_public(key, publicKey.Length, key);
                if (ret != 0)
                {
                    Marshal.FreeHGlobal(key);
                    key = IntPtr.Zero;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Curve25519 import public key exception " + e.ToString());
                if (key != IntPtr.Zero) Marshal.FreeHGlobal(key);
                key = IntPtr.Zero;
            }

            return key;
        }

        /// <summary>
        /// Export a Curve25519 private key to a byte array
        /// </summary>
        /// <param name="key">Curve25519 key structure</param>
        /// <returns>Private key as byte array</returns>
        public static byte[] Curve25519ExportPrivateKey(IntPtr key)
        {
            byte[] privateKey = new byte[ED25519_KEY_SIZE];
            uint privSize = (uint)privateKey.Length;
            int ret = wc_curve25519_export_public(key, privateKey, ref privSize);
            if (ret != 0)
            {
                throw new Exception("Failed to export Curve25519 private key. Error code: " + ret);
            }
            return privateKey;
        }

        /// <summary>
        /// Export a Curve25519 public key to a byte array
        /// </summary>
        /// <param name="key">Curve25519 key structure</param>
        /// <returns>Public key as byte array</returns>
        public static byte[] Curve25519ExportPublicKey(IntPtr key)
        {
            byte[] publicKey = new byte[ED25519_PUB_KEY_SIZE];
            uint pubSize = (uint)publicKey.Length;
            int ret = wc_curve25519_export_public(key, publicKey, ref pubSize);
            if (ret != 0)
            {
                throw new Exception("Failed to export Curve25519 public key. Error code: " + ret);
            }
            return publicKey;
        }

        /// <summary>
        /// Export both private and public keys from a Curve25519 key structure
        /// </summary>
        /// <param name="key">Curve25519 key structure</param>
        /// <returns>A tuple containing the private key and public key as byte arrays</returns>
        public static (byte[] privateKey, byte[] publicKey) Curve25519ExportKeyRaw(IntPtr key)
        {
            byte[] privateKey = new byte[ED25519_KEY_SIZE];
            byte[] publicKey = new byte[ED25519_PUB_KEY_SIZE];
            uint privSize = (uint)privateKey.Length;
            uint pubSize = (uint)publicKey.Length;
            int ret = wc_curve25519_export_key_raw(key, privateKey, ref privSize, publicKey, ref pubSize);
            if (ret != 0)
            {
                throw new Exception("Failed to export Curve25519 keys. Error code: " + ret);
            }
            return (privateKey, publicKey);
        }
        /* END RAW Curve25519 */


        /***********************************************************************
         * AES-GCM
         **********************************************************************/

        /// <summary>
        /// Creates a new AES context.
        /// </summary>
        /// <param name="heap">Pointer to a memory heap, or IntPtr.Zero to use the default heap.</param>
        /// <param name="devId">The device ID to associate with this AES context.</param>
        /// <returns>A pointer to the newly created AES context, or IntPtr.Zero on failure.</returns>
        public static IntPtr AesNew(IntPtr heap, int devId)
        {
            IntPtr aesPtr = IntPtr.Zero;

            try
            {
                aesPtr = wc_AesNew(heap, devId, IntPtr.Zero);

                if (aesPtr == IntPtr.Zero)
                {
                    throw new Exception("Failed to create AES context.");
                }

            }
            catch (Exception e)
            {
                Console.WriteLine($"AES context creation failed: {e.Message}");
            }

            return aesPtr;
        }

        /// <summary>
        /// Initialize and set the AES key for AES-GCM operations.
        /// </summary>
        /// <param name="aes">AES-GCM context pointer.</param>
        /// <param name="key">The AES key (either 128, 192, or 256 bits).</param>
        /// <returns>0 on success, otherwise an error code.</returns>
        public static int AesGcmSetKey(IntPtr aes, byte[] key)
        {
            IntPtr keyPtr = IntPtr.Zero;
            int ret;

            try
            {
                /* Allocate memory */
                keyPtr = Marshal.AllocHGlobal(key.Length);
                Marshal.Copy(key, 0, keyPtr, key.Length);

                ret = wc_AesGcmSetKey(aes, keyPtr, (uint)key.Length);
                if (ret != 0)
                {
                    throw new Exception($"AES-GCM initialization failed with error code {ret}");
                }
            }
            finally
            {
                /* Cleanup */
                if (keyPtr != IntPtr.Zero) Marshal.FreeHGlobal(keyPtr);
            }

            return ret;
        }

        /// <summary>
        /// Wrapper method to initialize the AES-GCM context with a given key and IV.
        /// </summary>
        /// <param name="aes">Pointer to the AES-GCM context that needs to be initialized.</param>
        /// <param name="key">Byte array containing the AES key.</param>
        /// <param name="iv">Byte array containing the initialization vector (IV).</param>
        public static int AesGcmInit(IntPtr aes, byte[] key, byte[] iv)
        {
            IntPtr keyPtr = IntPtr.Zero;
            IntPtr ivPtr = IntPtr.Zero;
            int ret;

            try
            {
                /* Allocate memory for key and IV */
                keyPtr = Marshal.AllocHGlobal(key.Length);
                Marshal.Copy(key, 0, keyPtr, key.Length);

                ivPtr = Marshal.AllocHGlobal(iv.Length);
                Marshal.Copy(iv, 0, ivPtr, iv.Length);

                ret = wc_AesGcmInit(aes, keyPtr, (uint)key.Length, ivPtr, (uint)iv.Length);
                if (ret != 0)
                {
                    throw new Exception($"AES-GCM initialization failed with error code {ret}");
                }
            }
            finally
            {
                /* Cleanup */
                if (keyPtr != IntPtr.Zero) Marshal.FreeHGlobal(keyPtr);
                if (ivPtr != IntPtr.Zero) Marshal.FreeHGlobal(ivPtr);
            }

            return ret;
        }

        /// <summary>
        /// Encrypt data using AES-GCM
        /// </summary>
        /// <param name="aes">AES-GCM context pointer.</param>
        /// <param name="iv">Initialization Vector (IV)</param>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="ciphertext">Buffer to receive the encrypted data</param>
        /// <param name="authTag">Buffer to receive the authentication tag</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int AesGcmEncrypt(IntPtr aes, byte[] iv, byte[] plaintext,
            byte[] ciphertext, byte[] authTag, byte[] addAuth = null)
        {
            int ret;
            IntPtr ivPtr = IntPtr.Zero;
            IntPtr ciphertextPtr = IntPtr.Zero;
            IntPtr plaintextPtr = IntPtr.Zero;
            IntPtr authTagPtr = IntPtr.Zero;
            IntPtr addAuthPtr = IntPtr.Zero;
            uint addAuthSz = 0;

            try
            {
                /* Allocate memory */
                ivPtr = Marshal.AllocHGlobal(iv.Length);
                ciphertextPtr = Marshal.AllocHGlobal(ciphertext.Length);
                plaintextPtr = Marshal.AllocHGlobal(plaintext.Length);
                authTagPtr = Marshal.AllocHGlobal(authTag.Length);
                if (addAuth != null) {
                    addAuthSz = (uint)addAuth.Length;
                    addAuthPtr = Marshal.AllocHGlobal(addAuth.Length);
                    Marshal.Copy(addAuth, 0, addAuthPtr, addAuth.Length);
                }

                Marshal.Copy(iv, 0, ivPtr, iv.Length);
                Marshal.Copy(plaintext, 0, plaintextPtr, plaintext.Length);

                /* Encrypt data */
                ret = wc_AesGcmEncrypt(aes, ciphertextPtr, plaintextPtr, (uint)plaintext.Length,
                    ivPtr, (uint)iv.Length, authTagPtr, (uint)authTag.Length, addAuthPtr, addAuthSz);
                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to Encrypt data using AES-GCM. Error code: " + ret);
                }
                else {
                    Marshal.Copy(ciphertextPtr, ciphertext, 0, ciphertext.Length);
                    Marshal.Copy(authTagPtr, authTag, 0, authTag.Length);
                    ret = 0;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "AES-GCM Encryption failed: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (ivPtr != IntPtr.Zero) Marshal.FreeHGlobal(ivPtr);
                if (ciphertextPtr != IntPtr.Zero) Marshal.FreeHGlobal(ciphertextPtr);
                if (plaintextPtr != IntPtr.Zero) Marshal.FreeHGlobal(plaintextPtr);
                if (authTagPtr != IntPtr.Zero) Marshal.FreeHGlobal(authTagPtr);
                if (addAuthPtr != IntPtr.Zero) Marshal.FreeHGlobal(addAuthPtr);
            }

            return ret;
        }

        /// <summary>
        /// Decrypt data using AES-GCM
        /// </summary>
        /// <param name="aes">AES-GCM context pointer.</param>
        /// <param name="iv">Initialization Vector (IV)</param>
        /// <param name="ciphertext">Data to decrypt</param>
        /// <param name="plaintext">Buffer to receive the decrypted data</param>
        /// <param name="authTag">Authentication tag for verification</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int AesGcmDecrypt(IntPtr aes, byte[] iv, byte[] ciphertext,
            byte[] plaintext, byte[] authTag, byte[] addAuth = null)
        {
            int ret;
            IntPtr ivPtr = IntPtr.Zero;
            IntPtr ciphertextPtr = IntPtr.Zero;
            IntPtr plaintextPtr = IntPtr.Zero;
            IntPtr authTagPtr = IntPtr.Zero;
            IntPtr addAuthPtr = IntPtr.Zero;
            uint addAuthSz = 0;

            try
            {
                /* Allocate memory */
                ivPtr = Marshal.AllocHGlobal(iv.Length);
                ciphertextPtr = Marshal.AllocHGlobal(ciphertext.Length);
                plaintextPtr = Marshal.AllocHGlobal(plaintext.Length);
                authTagPtr = Marshal.AllocHGlobal(authTag.Length);
                if (addAuth != null) {
                    addAuthSz = (uint)addAuth.Length;
                    addAuthPtr = Marshal.AllocHGlobal(addAuth.Length);
                    Marshal.Copy(addAuth, 0, addAuthPtr, addAuth.Length);
                }

                Marshal.Copy(iv, 0, ivPtr, iv.Length);
                Marshal.Copy(ciphertext, 0, ciphertextPtr, ciphertext.Length);
                Marshal.Copy(authTag, 0, authTagPtr, authTag.Length);

                /* Decrypt data */
                ret = wc_AesGcmDecrypt(aes, plaintextPtr, ciphertextPtr, (uint)ciphertext.Length,
                    ivPtr, (uint)iv.Length, authTagPtr, (uint)authTag.Length, addAuthPtr, addAuthSz);
                if (ret < 0)
                {
                    log(ERROR_LOG, "Failed to Decrypt data using AES-GCM. Error code: " + ret);
                }
                else {
                    Marshal.Copy(plaintextPtr, plaintext, 0, plaintext.Length);
                    ret = 0;
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "AES-GCM Decryption failed: " + e.ToString());
                ret = EXCEPTION_E;
            }
            finally
            {
                /* Cleanup */
                if (ivPtr != IntPtr.Zero) Marshal.FreeHGlobal(ivPtr);
                if (ciphertextPtr != IntPtr.Zero) Marshal.FreeHGlobal(ciphertextPtr);
                if (plaintextPtr != IntPtr.Zero) Marshal.FreeHGlobal(plaintextPtr);
                if (authTagPtr != IntPtr.Zero) Marshal.FreeHGlobal(authTagPtr);
                if (addAuthPtr != IntPtr.Zero) Marshal.FreeHGlobal(addAuthPtr);
            }

            return ret;
        }

        /// <summary>
        /// Free AES-GCM context
        /// </summary>
        /// <param name="aes">AES-GCM context</param>
        public static void AesGcmFree(IntPtr aes)
        {
            if (aes != IntPtr.Zero)
            {
                wc_AesDelete(aes, IntPtr.Zero);
                aes = IntPtr.Zero;
            }
        }
        /* END AES-GCM */


        /***********************************************************************
         * HASH
         **********************************************************************/

        /// <summary>
        /// Allocate and set up a new hash context with proper error handling
        /// </summary>
        /// <param name="hashType">The type of hash (SHA-256, SHA-384, etc.)</param>
        /// <param name="heap">Pointer to the heap for memory allocation (use IntPtr.Zero if not applicable)</param>
        /// <param name="devId">Device ID (if applicable, otherwise use INVALID_DEVID)</param>
        /// <returns>Allocated hash context pointer or IntPtr.Zero on failure</returns>
        public static IntPtr HashNew(uint hashType, IntPtr heap, int devId)
        {
            IntPtr hash = IntPtr.Zero;

            try
            {
                /* Allocate new hash */
                hash = wc_HashNew(hashType, heap, devId, IntPtr.Zero);
                if (hash == IntPtr.Zero)
                {
                    throw new Exception("Failed to allocate new hash context.");
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "HashNew Exception: " + e.ToString());
            }

            return hash;
        }

        /// <summary>
        /// Initialize the hash context for a specific hash type with proper error handling
        /// </summary>
        /// <param name="hash">Hash context pointer</param>
        /// <param name="hashType">The type of hash (SHA-256, SHA-384, etc.)</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int InitHash(IntPtr hash, uint hashType)
        {
            int ret = 0;

            try
            {
                /* Check hash */
                if (hash == IntPtr.Zero)
                    throw new Exception("Hash context is null.");

                ret = wc_HashInit(hash, hashType);
                if (ret != 0)
                {
                    throw new Exception($"Failed to initialize hash context. Error code: {ret}");
                }
            }
            catch (Exception e)
            {
                /* Cleanup */
                log(ERROR_LOG, "InitHash Exception: " + e.ToString());
                if (hash != IntPtr.Zero) {
                    wc_HashDelete(hash, IntPtr.Zero);
                    hash = IntPtr.Zero;
                }
            }

            return ret;
        }

        /// <summary>
        /// Update the hash with data
        /// </summary>
        /// <param name="hash">Hash context pointer</param>
        /// <param name="hashType">The type of hash</param>
        /// <param name="data">Byte array of the data to hash</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int HashUpdate(IntPtr hash, uint hashType, byte[] data)
        {
            int ret = 0;
            IntPtr dataPtr = IntPtr.Zero;

            try
            {
                /* Check parameters */
                if (hash == IntPtr.Zero)
                    throw new Exception("Hash context is null.");
                if (data == null || data.Length == 0)
                    throw new Exception("Invalid data array.");

                /* Allocate memory */
                dataPtr = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, dataPtr, data.Length);

                /* Update hash */
                ret = wc_HashUpdate(hash, hashType, dataPtr, (uint)data.Length);
                if (ret != 0)
                {
                    throw new Exception($"Failed to update hash. Error code: {ret}");
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "HashUpdate Exception: " + e.ToString());
            }
            finally
            {
                /* Cleanup */
                if (dataPtr != IntPtr.Zero) Marshal.FreeHGlobal(dataPtr);
            }

            return ret;
        }

        /// <summary>
        /// Finalize the hash and output the result
        /// </summary>
        /// <param name="hash">Hash context pointer</param>
        /// <param name="hashType">The type of hash</param>
        /// <param name="output">Byte array where the hash output will be stored</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int HashFinal(IntPtr hash, uint hashType, out byte[] output)
        {
            int ret = 0;
            IntPtr outputPtr = IntPtr.Zero;

            try
            {
                /* Get hash size and initialize */
                int hashSize = wc_HashGetDigestSize(hashType);
                output = new byte[hashSize];

                /* Check hash */
                if (hash == IntPtr.Zero)
                    throw new Exception("Hash context is null.");
                if (hashSize <= 0)
                    throw new Exception("Invalid hash size.");

                /* Allocate memory */
                outputPtr = Marshal.AllocHGlobal(hashSize);

                ret = wc_HashFinal(hash, hashType, outputPtr);
                if (ret != 0)
                {
                    throw new Exception($"Failed to finalize hash. Error code: {ret}");
                }

                Marshal.Copy(outputPtr, output, 0, hashSize);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "HashFinal Exception: " + e.ToString());
                output = null;
            }
            finally
            {
                /* Cleanup */
                if (outputPtr != IntPtr.Zero) Marshal.FreeHGlobal(outputPtr);
            }

            return ret;
        }

        /// <summary>
        /// Free the allocated hash context with proper error handling
        /// </summary>
        /// <param name="hash">Hash context pointer to be freed</param>
        /// <param name="hashType">The type of hash</param>
        /// <returns>0 on success, otherwise an error code</returns>
        public static int HashFree(IntPtr hash, uint hashType)
        {
            int ret = 0;

            try
            {
                /* Check hash */
                if (hash == IntPtr.Zero)
                    throw new Exception("Hash context is null, cannot free.");

                /* Free hash */
                ret = wc_HashDelete(hash, IntPtr.Zero);
                hash = IntPtr.Zero;
                if (ret != 0)
                {
                    throw new Exception($"Failed to free hash context. Error code: {ret}");
                }
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "HashFree Exception: " + e.ToString());
            }

            return ret;
        }

        /// <summary>
        /// Hash type enum values
        /// </summary>
        public enum hashType
        {
            WC_HASH_TYPE_NONE     = 0,
            WC_HASH_TYPE_MD2      = 1,
            WC_HASH_TYPE_MD4      = 2,
            WC_HASH_TYPE_MD5      = 3,
            WC_HASH_TYPE_SHA      = 4, /* SHA-1 (not old SHA-0) */
            WC_HASH_TYPE_SHA224   = 5,
            WC_HASH_TYPE_SHA256   = 6,
            WC_HASH_TYPE_SHA384   = 7,
            WC_HASH_TYPE_SHA512   = 8,
            WC_HASH_TYPE_MD5_SHA  = 9,
            WC_HASH_TYPE_SHA3_224 = 10,
            WC_HASH_TYPE_SHA3_256 = 11,
            WC_HASH_TYPE_SHA3_384 = 12,
            WC_HASH_TYPE_SHA3_512 = 13,
            WC_HASH_TYPE_BLAKE2B  = 14,
            WC_HASH_TYPE_BLAKE2S  = 15,
        }
        /* END HASH */


        /***********************************************************************
        * Logging / Other
        **********************************************************************/

        /// <summary>
        /// Set the function to use for logging
        /// </summary>
        /// <param name="input">Function that conforms as to loggingCb</param>
        /// <returns>0 on success</returns>
        public static int SetLogging(loggingCb input)
        {
            internal_log = input;
            return SUCCESS;
        }

        /// <summary>
        /// Get error string for wolfCrypt error codes
        /// </summary>
        /// <param name="error">Negative error number from wolfCrypt API</param>
        /// <returns>Error string</returns>
        public static string GetError(int error)
        {
            try
            {
                IntPtr errStr = wc_GetErrorString(error);
                return Marshal.PtrToStringAnsi(errStr);
            }
            catch (Exception e)
            {
                log(ERROR_LOG, "Get error exception " + e.ToString());
                return string.Empty;
            }
        }

        /// <summary>
        /// Compares two byte arrays.
        /// </summary>
        /// <param name="array1">The first byte array to compare.</param>
        /// <param name="array2">The second byte array to compare.</param>
        /// <returns>True if both arrays are equal; otherwise, false.</returns>
        public static bool ByteArrayVerify(byte[] array1, byte[] array2)
        {
            if (ReferenceEquals(array1, array2)) return true;
            if (array1 == null || array2 == null) return false;
            if (array1.Length != array2.Length) return false;

            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i]) return false;
            }
            return true;
        }
    }
}


