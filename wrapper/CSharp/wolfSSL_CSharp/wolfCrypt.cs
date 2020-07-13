/* wolfCrypt.cs
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
using System.Text;
using System.Threading;
using System.IO;

namespace wolfSSL.CSharp {
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
        private extern static int wc_ecc_make_key_ex(IntPtr rng, int keysize, IntPtr key, int curve_id);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_sign_hash(IntPtr hashPtr, uint hashlen, IntPtr sigPtr, IntPtr siglen, IntPtr rng, IntPtr key);
        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_ecc_verify_hash(IntPtr sigPtr, uint siglen, IntPtr hashPtr, uint hashlen, IntPtr res, IntPtr key);

        [DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
        private extern static int wc_EccPrivateKeyDecode(IntPtr keyBuf, IntPtr idx, IntPtr key, uint keyBufSz);

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

        [DllImport("kernel32.dll", EntryPoint = "RtlFillMemory", SetLastError = false)]
        private extern static void RtlFillMemory(IntPtr destination, uint length, byte fill);

        /********************************
         * Enum types from wolfSSL library
         */
        
        /* Logging levels */
        public static readonly int ERROR_LOG = 0;
        public static readonly int INFO_LOG = 1;
        public static readonly int ENTER_LOG = 2;
        public static readonly int LEAVE_LOG = 3;
        public static readonly int OTHER_LOG = 4;

        /* Error codes */
        public static readonly int SUCCESS = 0;
        public static readonly int MEMORY_E = -125; /* out of memory error */
        public static readonly int EXCEPTION_E = -1;


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
            try {
                ret = wolfCrypt_Init();
            }
            catch (Exception e) {
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
            try {
                ret = wolfCrypt_Cleanup();
            }
            catch (Exception e) {
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
            try {
                /* Allocate and init new WC_RNG structure */
                rng = wc_rng_new(
                    IntPtr.Zero, 0, /* Nonce (optional / used by FIPS only) */
                    IntPtr.Zero);   /* Heap hint for static memory only */
            } 
            catch (Exception e) {
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
            if (rng != IntPtr.Zero) {
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
            
            try {
                /* Allocate global buffer for wolfAPI random */
                data = Marshal.AllocHGlobal(sz);
                if (data != IntPtr.Zero) {
                    /* Generate random block */
                    ret = wc_RNG_GenerateBlock(rng, data, Convert.ToUInt32(sz));
                    if (ret == 0) {
                        /* copy returned data */
                        Marshal.Copy(data, buf, 0, sz);
                    }
                    else {
                        log(ERROR_LOG, "random generate block error " + ret + ": " + GetError(ret));
                    }
                    Marshal.FreeHGlobal(data);
                }
                else {
                    ret = MEMORY_E;
                }
            } 
            catch (Exception e) {
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
            if (rng == IntPtr.Zero) {
                return MEMORY_E;
            }
            ret = Random(rng, buf, sz);
            RandomFree(rng);
            return ret;
        }


        /***********************************************************************
         * ECC
         **********************************************************************/

        /// <summary>
        /// Generate a new ECC private / public key pair
        /// </summary>
        /// <param name="keysize">Key size in bytes (example: SECP256R1 = 32)</param>
        /// <returns>Allocated ECC key structure or null</returns>
        public static IntPtr EccMakeKey(int keysize)
        {
            int ret;
            IntPtr key = IntPtr.Zero;
            IntPtr rng = IntPtr.Zero;
            try {
                /* Allocate and init new WC_RNG structure */
                key = wc_ecc_key_new(IntPtr.Zero);
                if (key != IntPtr.Zero) {
                    rng = RandomNew();
                    ret = wc_ecc_make_key_ex(rng, keysize, key, 0); /* 0=use default curve */
                    if (ret != 0) {
                        EccFreeKey(key);
                        key = IntPtr.Zero;
                    }
                    RandomFree(rng);
                    rng = IntPtr.Zero;
                }
            }
            catch (Exception e) {
                log(ERROR_LOG, "ECC make key exception " + e.ToString());
                RandomFree(rng);
                EccFreeKey(key);
                key = IntPtr.Zero;
            }
            return key;
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
            try {
                key = wc_ecc_key_new(IntPtr.Zero);
                if (key != IntPtr.Zero) {
                    IntPtr idx = Marshal.AllocHGlobal(sizeof(uint));
                    IntPtr keydata = Marshal.AllocHGlobal(keyASN1.Length);
                    RtlFillMemory(idx, sizeof(uint), 0); /* zero init */
                    Marshal.Copy(keyASN1, 0, keydata, keyASN1.Length);
                    ret = wc_EccPrivateKeyDecode(keydata, idx, key, Convert.ToUInt32(keyASN1.Length));
                    if (ret != 0) {
                        EccFreeKey(key);
                        key = IntPtr.Zero;
                    }
                    Marshal.FreeHGlobal(idx); /* not used */
                    Marshal.FreeHGlobal(keydata);
                }
            }
            catch (Exception e) {
                log(ERROR_LOG, "ECC make key exception " + e.ToString());
                EccFreeKey(key); /* make sure its free'd */
                key = IntPtr.Zero;
            }
            return key;
        }

        public static int EccSign(IntPtr key, byte[] hash, byte[] signature)
        {
            //private extern static int wc_ecc_sign_hash(IntPtr inPtr, UInt32 inlen, IntPtr outPtr, IntPtr outlen, IntPtr rng, IntPtr key);
            return SUCCESS;
        }

        public static int EccVerify(IntPtr key, byte[] signature, byte[] hash)
        {
            //private extern static int wc_ecc_verify_hash(IntPtr sigPtr, UInt32 siglen, IntPtr hashPtr, UInt32 hashlen, IntPtr res, IntPtr key);
            return SUCCESS;
        }

        /// <summary>
        /// Free an ECC key structure
        /// </summary>
        /// <param name="key">ECC key structure allocated using EccMakeKey() or EccImportKey()</param>
        public static void EccFreeKey(IntPtr key)
        {
            if (key != IntPtr.Zero) {
                wc_ecc_key_free(key);
            }
        }



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
            try {
                IntPtr errStr = wc_GetErrorString(error);
                return Marshal.PtrToStringAnsi(errStr);
            }
            catch (Exception e) {
                log(ERROR_LOG, "Get error exception " + e.ToString());
                return string.Empty;
            }
        }
    }
}
