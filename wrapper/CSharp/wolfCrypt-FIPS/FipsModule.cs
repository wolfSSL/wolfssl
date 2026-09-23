/* FipsModule.cs
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
    /* enum FipsModeId, fips_test.h (v5.2.3) */
    public enum FipsMode
    {
        Init = 0,
        Normal = 1,
        Degraded = 2,
        Failed = 3
    }

    /* enum FipsCastId, fips_test.h (v5.2.3). 15 CASTs. */
    public enum FipsCast
    {
        AesCbc = 0,
        AesGcm = 1,
        HmacSha1 = 2,
        HmacSha2_256 = 3,
        HmacSha2_512 = 4,
        HmacSha3_256 = 5,
        Drbg = 6,
        RsaSignPkcs1v15 = 7,
        EccCdh = 8,
        EccPrimitiveZ = 9,
        DhPrimitiveZ = 10,
        Ecdsa = 11,
        KdfTls12 = 12,
        KdfTls13 = 13,
        KdfSsh = 14
    }

    /* enum FipsCastStateId, fips_test.h (v5.2.3) */
    public enum FipsCastState
    {
        Init = 0,
        Processing = 1,
        Success = 2,
        Failure = 3
    }

    /* Callback invoked by the module on a self-test failure. ok is 0 on
     * failure, err is the error code, hash is the computed in-core hash. */
    public delegate void FipsFailureCallback(int ok, int err, string? hash);

    /* Custom DRBG seed source: fill sz bytes at seed, return 0 on success.
     * os is an opaque native OS_Seed pointer. */
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int FipsSeedCallback(IntPtr os, IntPtr seed, uint sz);

    /* Module-level FIPS services: status, mode, self-tests, integrity. */
    public static class FipsModule
    {
        public const int CastCount = 15;

        /* Holds the native delegate so the GC cannot collect it while the
         * module still has it registered. */
        private static Native.FipsCallback? nativeCallback;
        private static FipsFailureCallback? userCallback;
        private static FipsSeedCallback? customSeed;
        private static readonly object cbLock = new object();

        /* Recommended startup call. Call before any other cryptographic use.
         *
         * 1. Loads the native library, which runs the power-on self-tests and
         *    in-core integrity check in the library constructor.
         * 2. Optionally registers a failure callback.
         * 3. Registers the DRBG seed source. The module has no entropy source
         *    of its own; in WC_RNG_SEED_CB builds nothing that needs the DRBG
         *    works until a seed source is registered (including the ECC
         *    CASTs). Default: the library's OS entropy function.
         * 4. Throws if the module is not operational. */
        public static void Initialize(FipsFailureCallback? onFailure = null,
                                      bool useOsSeed = true)
        {
            if (onFailure != null)
                SetFailureCallback(onFailure);
            if (useOsSeed)
                UseOsSeed();
            int status = Native.wolfCrypt_GetStatus_fips();
            if (status != 0)
                throw new WolfCryptFipsException("wolfCrypt_GetStatus_fips", status);
            FipsMode mode = Mode;
            if (mode != FipsMode.Normal)
                throw new WolfCryptFipsException("wolfCrypt_GetMode_fips",
                    mode == FipsMode.Degraded ? FipsError.FIPS_DEGRADED_E
                                              : FipsError.FIPS_NOT_ALLOWED_E);
        }

        /* 0 when the module is operational, otherwise the failing error. */
        public static int Status => Native.wolfCrypt_GetStatus_fips();

        public static FipsMode Mode => (FipsMode)Native.wolfCrypt_GetMode_fips();

        public static bool IsOperational => Status == 0 && Mode == FipsMode.Normal;

        /* In-core hash computed by the power-on self-test. The module keeps
         * it only when the integrity check fails (it is cleared after a
         * successful check), so this is empty on an operational module. On
         * failure it is the value to place in verifyCore[]. */
        public static string? CoreHash =>
            Marshal.PtrToStringAnsi(Native.wolfCrypt_GetCoreHash_fips());

        /* Module version string, e.g. "v5.2.3". */
        public static string? Version =>
            Marshal.PtrToStringAnsi(Native.wolfCrypt_GetVersion_fips());

        /* Operator-initiated re-run of the in-core integrity test. */
        public static int IntegrityTest() => Native.wolfCrypt_IntegrityTest_fips();

        public static int RunAllCasts() => Native.wc_RunAllCast_fips();

        public static int RunCast(FipsCast cast) => Native.wc_RunCast_fips((int)cast);

        public static FipsCastState GetCastState(FipsCast cast) =>
            (FipsCastState)Native.wc_GetCastStatus_fips((int)cast);

        public static void SetFailureCallback(FipsFailureCallback cb)
        {
            lock (cbLock) {
                userCallback = cb;
                nativeCallback = (ok, err, hash) =>
                    userCallback?.Invoke(ok, err, Marshal.PtrToStringAnsi(hash));
                WolfCryptFipsException.Check("wolfCrypt_SetCb_fips",
                    Native.wolfCrypt_SetCb_fips(nativeCallback));
            }
        }

        /* Registers the library's OS entropy function (wc_GenerateSeed,
         * /dev/urandom on Linux) as the DRBG seed source. The function
         * pointer is passed straight to the module; no managed code is in
         * the entropy path. */
        public static void UseOsSeed()
        {
            IntPtr fn = NativeLibrary.GetExport(NativeLoader.WolfsslHandle(), Native.OS_SEED_EXPORT);
            WolfCryptFipsException.Check("wc_SetSeed_Cb_fips", Native.wc_SetSeed_Cb_fips(fn));
        }

        /* Registers a custom seed source (for example a hardware TRNG). The
         * delegate is held for the life of the process. */
        public static void SetSeedCallback(FipsSeedCallback cb)
        {
            lock (cbLock) {
                customSeed = cb;
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(customSeed);
                WolfCryptFipsException.Check("wc_SetSeed_Cb_fips", Native.wc_SetSeed_Cb_fips(fn));
            }
        }

        /* Private key export gate (WC_KEYTYPE_ALL). Export of private keys
         * is locked by default in the module.
         *
         * The gate is per thread: the module keeps it in thread-local
         * storage. Enable it and export on the same thread; with async code
         * do not await between the two. */
        public static void SetPrivateKeyReadEnable(bool enable) =>
            WolfCryptFipsException.Check("wolfCrypt_SetPrivateKeyReadEnable_fips",
                Native.wolfCrypt_SetPrivateKeyReadEnable_fips(enable ? 1 : 0, 0));

        public static bool PrivateKeyReadEnabled =>
            Native.wolfCrypt_GetPrivateKeyReadEnable_fips(0) != 0;

        /* Failure injection for operational testing. Only libraries built
         * with HAVE_FORCE_FIPS_FAILURE export wolfCrypt_SetStatus_fips.
         * Internal: exposed to the test assembly only. */
        internal static bool CanInjectFailure =>
            NativeLibrary.TryGetExport(NativeLoader.WolfsslHandle(), "wolfCrypt_SetStatus_fips", out _);

        internal static int InjectFailure(int code) => Native.wolfCrypt_SetStatus_fips(code);

        /* Runs an operation whose purpose is to return an SSP-bearing value
         * (shared secret, generated key pair, derived key) with the private
         * key read gate enabled on this thread, then restores the previous
         * state. Mirrors wolfSSL's own PRIVATE_KEY_UNLOCK()/LOCK() use around
         * these calls. The operation must be synchronous (the gate is per
         * thread). Bulk private key export (FipsRsaKey.Export) does not use
         * this and stays under explicit caller control. */
        internal static TR WithPrivateKeyRead<TR>(Func<TR> op)
        {
            bool prev = PrivateKeyReadEnabled;
            if (!prev)
                SetPrivateKeyReadEnable(true);
            try {
                return op();
            }
            finally {
                if (!prev)
                    SetPrivateKeyReadEnable(false);
            }
        }
    }
}
