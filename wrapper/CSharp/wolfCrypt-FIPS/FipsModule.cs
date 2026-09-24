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
using System.Threading;

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

        /* Every delegate ever handed to the module, kept for the life of
         * the process: native code may still hold (and call) a previously
         * registered function pointer, for example if a later registration
         * is refused or races with a DRBG reseed on another thread. */
        private static readonly System.Collections.Generic.List<Delegate> registered = new();
        private static readonly object cbLock = new object();

        /* True once SetSeedCallback registered a custom seed source;
         * Initialize then leaves it in place. */
        private static bool customSeed;

        /* Recommended startup call. Call before any other cryptographic use.
         *
         * 1. Loads the native library, which runs the power-on self-tests and
         *    in-core integrity check in the library constructor.
         * 2. Optionally registers a failure callback.
         * 3. Registers the DRBG seed source. The module has no entropy source
         *    of its own; in WC_RNG_SEED_CB builds nothing that needs the DRBG
         *    works until a seed source is registered (including the ECC
         *    CASTs). Default: the library's OS entropy function, unless a
         *    custom source was already registered with SetSeedCallback, which
         *    is kept (so SetSeedCallback may be called before or after
         *    Initialize, and later Initialize calls do not replace it).
         *    Pass useOsSeed: false to register no source here.
         * 4. Throws if the module is not operational. */
        public static void Initialize(FipsFailureCallback? onFailure = null,
                                      bool useOsSeed = true)
        {
            if (onFailure != null)
                SetFailureCallback(onFailure);
            EnsureHelperMatchesModule();
            if (useOsSeed) {
                lock (cbLock) {
                    if (!customSeed)
                        RegisterOsSeed();
                }
            }
            int status = Native.wolfCrypt_GetStatus_fips();
            if (status != 0)
                throw new WolfCryptFipsException("wolfCrypt_GetStatus_fips", status);
            FipsMode mode = Mode;
            if (mode != FipsMode.Normal)
                throw new WolfCryptFipsException("wolfCrypt_GetMode_fips",
                    mode == FipsMode.Degraded ? FipsError.FIPS_DEGRADED_E
                                              : FipsError.FIPS_NOT_ALLOWED_E);
        }

        /* The size helper must be built from the same install as the module
         * (struct sizes depend on the build). Compares the FIPS major.minor
         * the helper was compiled for with the module's version string. The
         * patch level is not compared: v5.2.3 drops stamp HAVE_FIPS_VERSION
         * 5.2.1 in options.h. */
        internal static void CheckHelperMatchesModule()
        {
            /* exact binary: the helper must have been built (build-native.sh)
             * against the libwolfssl file that is actually loaded */
            uint crc = (uint)Native.SizeOf((int)FipsStructType.LibCrc);
            int size = Native.SizeOf((int)FipsStructType.LibSize);
            string lib = NativeLoader.WolfsslPath;
            if (crc == 0 || size <= 0)
                throw new InvalidOperationException("size helper carries no library fingerprint; build it with build-native.sh");
            byte[] bytes = System.IO.File.ReadAllBytes(lib);
            if (bytes.Length != size || PosixCksum(bytes) != crc)
                throw new InvalidOperationException("size helper was built for a different libwolfssl binary than " + lib +
                    "; rebuild it with build-native.sh against this install");

            int mm = Native.SizeOf((int)FipsStructType.FipsVersionMM);
            var m = System.Text.RegularExpressions.Regex.Match(Version ?? "", @"v(\d+)\.(\d+)");
            if (mm <= 0 || !m.Success)
                throw new InvalidOperationException("cannot determine FIPS version of the size helper or the module");
            int moduleMM = int.Parse(m.Groups[1].Value) * 100 + int.Parse(m.Groups[2].Value);
            if (mm != moduleMM)
                throw new InvalidOperationException("size helper was built for FIPS v" + mm / 100 + "." + mm % 100 +
                    " but the loaded module is " + Version + "; rebuild it with build-native.sh against this install");
        }

        /* Verified once, before the first native structure is allocated. */
        private static readonly Lazy<Exception?> helperCheck = new(() => {
            try { CheckHelperMatchesModule(); return null; }
            catch (Exception e) { return e; }
        });

        internal static void EnsureHelperMatchesModule()
        {
            Exception? e = helperCheck.Value;
            if (e != null)
                throw new InvalidOperationException(e.Message, e);
        }

        /* POSIX cksum: CRC-32 (poly 0x04C11DB7, MSB first) over the data and
         * then the length, complemented. Build identity only, not a
         * security function. */
        internal static uint PosixCksum(byte[] data)
        {
            uint crc = 0;
            void Add(byte b)
            {
                crc ^= (uint)b << 24;
                for (int k = 0; k < 8; k++)
                    crc = (crc & 0x80000000) != 0 ? (crc << 1) ^ 0x04C11DB7 : crc << 1;
            }
            foreach (byte b in data)
                Add(b);
            for (long n = data.LongLength; n != 0; n >>= 8)
                Add((byte)(n & 0xff));
            return ~crc;
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

        /* Operator-initiated re-run of the in-core integrity test. Returns
         * the module status afterwards (0 when operational). The v5.2.x
         * wolfCrypt_IntegrityTest_fips always returns 0; a failed re-run is
         * visible only in the status and mode. */
        public static int IntegrityTest()
        {
            Native.wolfCrypt_IntegrityTest_fips();
            return Status;
        }

        public static int RunAllCasts() => Native.wc_RunAllCast_fips();

        /* The module does not range-check the CAST id before writing its
         * state array, so out-of-range values are refused here. */
        public static int RunCast(FipsCast cast)
        {
            if ((int)cast < 0 || (int)cast >= CastCount)
                throw new ArgumentOutOfRangeException(nameof(cast));
            return Native.wc_RunCast_fips((int)cast);
        }

        private static long refusedFrees;

        /* Number of wc_*Free_fips calls the module refused (FAILED state or
         * failed CAST). Each one left module-allocated memory behind the
         * structure unzeroized; see FipsHandle. */
        public static long RefusedFreeCount => Interlocked.Read(ref refusedFrees);

        internal static void NoteRefusedFree() => Interlocked.Increment(ref refusedFrees);

        public static FipsCastState GetCastState(FipsCast cast)
        {
            if ((int)cast < 0 || (int)cast >= CastCount)
                throw new ArgumentOutOfRangeException(nameof(cast));
            return (FipsCastState)Native.wc_GetCastStatus_fips((int)cast);
        }

        /* The callback runs on the module's thread from inside native code;
         * exceptions it throws are caught here (an exception crossing back
         * into native code would terminate the process). */
        public static void SetFailureCallback(FipsFailureCallback cb)
        {
            if (cb == null)
                throw new ArgumentNullException(nameof(cb));
            Native.FipsCallback native = (ok, err, hash) => {
                try { cb(ok, err, Marshal.PtrToStringAnsi(hash)); }
                catch { /* must not unwind into the module */ }
            };
            lock (cbLock) {
                registered.Add(native);
                WolfCryptFipsException.Check("wolfCrypt_SetCb_fips", Native.wolfCrypt_SetCb_fips(native));
            }
        }

        /* Registers the library's OS entropy function (wc_GenerateSeed,
         * /dev/urandom on Linux) as the DRBG seed source. The function
         * pointer is passed straight to the module; no managed code is in
         * the entropy path. An explicit call replaces any custom source. */
        public static void UseOsSeed()
        {
            lock (cbLock) {
                RegisterOsSeed();
                customSeed = false;
            }
        }

        private static void RegisterOsSeed()
        {
            IntPtr fn = NativeLibrary.GetExport(NativeLoader.WolfsslHandle(), Native.OS_SEED_EXPORT);
            WolfCryptFipsException.Check("wc_SetSeed_Cb_fips", Native.wc_SetSeed_Cb_fips(fn));
        }

        /* Registers a custom seed source (for example a hardware TRNG). The
         * delegate is held for the life of the process. Initialize does not
         * replace it; UseOsSeed does. */
        public static void SetSeedCallback(FipsSeedCallback cb)
        {
            if (cb == null)
                throw new ArgumentNullException(nameof(cb));
            /* an exception from cb is reported to the module as a seed
             * failure (non-zero) instead of unwinding into native code */
            FipsSeedCallback trampoline = (os, seed, sz) => {
                try { return cb(os, seed, sz); }
                catch { return -1; }
            };
            lock (cbLock) {
                registered.Add(trampoline);
                IntPtr fn = Marshal.GetFunctionPointerForDelegate(trampoline);
                WolfCryptFipsException.Check("wc_SetSeed_Cb_fips", Native.wc_SetSeed_Cb_fips(fn));
                customSeed = true;
            }
        }

        /* Private key export gate (WC_KEYTYPE_ALL). Export of private keys
         * is locked by default in the module.
         *
         * The gate is per thread: the module keeps it in thread-local
         * storage. Enable it and export on the same thread; with async code
         * do not await between the two. */
        /* The module keeps a per-thread nesting counter (so wolfSSL's own
         * PRIVATE_KEY_UNLOCK/LOCK pairs can nest). This is an on/off switch
         * over it: true opens the gate if closed; false closes it fully,
         * however many times it was opened. */
        public static void SetPrivateKeyReadEnable(bool enable)
        {
            if (enable) {
                if (!PrivateKeyReadEnabled)
                    WolfCryptFipsException.Check("wolfCrypt_SetPrivateKeyReadEnable_fips",
                        Native.wolfCrypt_SetPrivateKeyReadEnable_fips(1, 0));
                return;
            }
            for (int i = 0; i < 1024 && PrivateKeyReadEnabled; i++)
                WolfCryptFipsException.Check("wolfCrypt_SetPrivateKeyReadEnable_fips",
                    Native.wolfCrypt_SetPrivateKeyReadEnable_fips(0, 0));
            if (PrivateKeyReadEnabled)
                throw new InvalidOperationException("private key read gate could not be closed");
        }

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
