/* FipsRng.cs
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
using System.Security.Cryptography;
using System.Threading;

namespace wolfSSL.CSharp.Fips
{
    /* SHA-256 Hash_DRBG (SP 800-90A) instance from the FIPS module.
     *
     * Requires a seed source; FipsModule.Initialize() registers the OS
     * source by default. Every use, directly (Generate) or by another
     * service that is handed this DRBG (key generation, signing, IV
     * generation), takes the instance lock, so an instance may be shared
     * between threads.
     *
     * Every use also checks the module's DRBG CAST: once it has failed the
     * wrapper refuses the DRBG (DRBG_KAT_FIPS_E) even for services the
     * module itself would still serve from an existing instance.
     *
     * Custom seed sources: the module's automatic reseed (after 1,000,000
     * requests) takes entropy from wc_GenerateSeed, not from a callback
     * registered with FipsModule.SetSeedCallback (module behavior; see the
     * README). The callback covers instantiation only.
     *
     * Dispose is the zeroization procedure for the DRBG state (V, C): an
     * instance that is not disposed is zeroized only when the finalizer
     * runs, which .NET does not do at process exit. */
    public sealed class FipsRng : FipsObject
    {
        /* Largest single request the DRBG accepts (RNG_MAX_BLOCK_LEN of the
         * loaded build, read from the size helper: 0x10000 by default,
         * 0xFFFF with HAVE_INTEL_QA, or a build override). */
        public static int MaxRequest => FipsObject.StructSize(FipsStructType.RngMaxBlockLen);

        /* Output length of the module's DRBG health test
         * (RNG_HEALTH_TEST_CHECK_SIZE in random.c: 4 SHA-256 blocks). */
        public const int HealthTestOutputSize = 128;

        /* SP 800-90A 8.6.7: a caller nonce needs at least
         * security_strength / 2 = 128 bits. */
        public const int MinNonceSize = 16;

        private readonly object sync = new object();

        public FipsRng() : base(FipsStructType.Rng)
        {
            Init(Native.wc_InitRng_fips(Handle), "wc_InitRng_fips");
        }

        /* Instantiate with a caller-supplied nonce of at least 16 bytes
         * (SP 800-90A 8.6.7). Prefer the parameterless constructor, which
         * draws the nonce from the seed source. */
        public FipsRng(byte[] nonce) : base(FipsStructType.Rng)
        {
            if (nonce == null) {
                Dispose();
                throw new ArgumentNullException(nameof(nonce));
            }
            if (nonce.Length < MinNonceSize) {
                Dispose();
                throw new ArgumentException("DRBG nonce must be at least " + MinNonceSize +
                    " bytes (SP 800-90A 8.6.7)", nameof(nonce));
            }
            Init(Native.wc_InitRngNonce_fips(Handle, nonce, (uint)nonce.Length),
                 "wc_InitRngNonce_fips");
        }

        private void Init(int ret, string fn)
        {
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException(fn, ret);
            }
            SetNativeFree(p => Native.wc_FreeRng_fips(p));
        }

        /* Holds the instance lock for one module call that uses this DRBG. */
        internal readonly struct Lease : IDisposable
        {
            private readonly object? held;
            internal Lease(object held) { this.held = held; }
            public void Dispose()
            {
                if (held != null)
                    Monitor.Exit(held);
            }
        }

        /* Takes the lock and refuses a disposed instance or a failed DRBG
         * CAST. */
        internal Lease Use()
        {
            Monitor.Enter(sync);
            try {
                ThrowIfDisposed();
                if (FipsModule.GetCastState(FipsCast.Drbg) == FipsCastState.Failure)
                    throw new WolfCryptFipsException("DRBG CAST", FipsError.DRBG_KAT_FIPS_E);
                return new Lease(sync);
            }
            catch {
                Monitor.Exit(sync);
                throw;
            }
        }

        /* Fills buf with DRBG output. On any failure buf is cleared: the
         * module copies each block out as it is generated, so a continuous
         * test failure (DRBG_CONT_FIPS_E) would otherwise leave the blocks
         * produced before it in buf. */
        public void Generate(byte[] buf)
        {
            if (buf == null)
                throw new ArgumentNullException(nameof(buf));
            int ret;
            try {
                using (Use())
                    ret = Native.wc_RNG_GenerateBlock_fips(Handle, buf, (uint)buf.Length);
            }
            catch {
                CryptographicOperations.ZeroMemory(buf);
                throw;
            }
            if (ret != 0) {
                CryptographicOperations.ZeroMemory(buf);
                throw new WolfCryptFipsException("wc_RNG_GenerateBlock_fips", ret);
            }
        }

        /* Returns count bytes of DRBG output. */
        public byte[] Generate(int count)
        {
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            byte[] buf = new byte[count];
            Generate(buf);
            return buf;
        }

        /* DRBG known-answer health test (self-test service). Instantiates a
         * temporary DRBG with seedA, optionally reseeds with seedB
         * (reseed = true, seedB then required), generates twice and returns
         * the second block, for comparison against SP 800-90A test vectors.
         * The output is fully determined by the inputs: it is test output,
         * never random or key material, so this is internal. The module
         * produces exactly HealthTestOutputSize (128) bytes. */
        internal static byte[] HealthTest(bool reseed, byte[] seedA, byte[]? seedB,
                                          int outputLen = HealthTestOutputSize)
        {
            if (seedA == null)
                throw new ArgumentNullException(nameof(seedA));
            if (reseed && seedB == null)
                throw new ArgumentNullException(nameof(seedB), "reseed requires seedB");
            if (outputLen != HealthTestOutputSize)
                throw new ArgumentOutOfRangeException(nameof(outputLen),
                    "the module DRBG health test returns exactly " + HealthTestOutputSize + " bytes");
            byte[] output = new byte[outputLen];
            WolfCryptFipsException.Check("wc_RNG_HealthTest_fips",
                Native.wc_RNG_HealthTest_fips(reseed ? 1 : 0, seedA, (uint)seedA.Length,
                    seedB, seedB == null ? 0u : (uint)seedB.Length, output, (uint)outputLen));
            return output;
        }
    }
}
