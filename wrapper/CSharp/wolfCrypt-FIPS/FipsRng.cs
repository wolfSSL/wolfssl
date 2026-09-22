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

namespace wolfSSL.CSharp.Fips
{
    /* SHA-256 Hash_DRBG (SP 800-90A) instance from the FIPS module.
     *
     * Requires a seed source; FipsModule.Initialize() registers the OS
     * source by default. Instances are not thread-safe; use one per thread
     * or lock externally. */
    public sealed class FipsRng : FipsObject
    {
        /* Largest single request the DRBG accepts (RNG_MAX_BLOCK_LEN). */
        public const int MaxRequest = 0x10000;

        public FipsRng() : base(FipsStructType.Rng)
        {
            Init(Native.wc_InitRng_fips(Handle), "wc_InitRng_fips");
        }

        /* Instantiate with a caller-supplied nonce. */
        public FipsRng(byte[] nonce) : base(FipsStructType.Rng)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));
            Init(Native.wc_InitRngNonce_fips(Handle, nonce, (uint)nonce.Length),
                 "wc_InitRngNonce_fips");
        }

        private bool initialized;

        private void Init(int ret, string fn)
        {
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException(fn, ret);
            }
            initialized = true;
        }

        /* Fills buf with DRBG output. */
        public void Generate(byte[] buf)
        {
            if (buf == null)
                throw new ArgumentNullException(nameof(buf));
            ThrowIfDisposed();
            WolfCryptFipsException.Check("wc_RNG_GenerateBlock_fips",
                Native.wc_RNG_GenerateBlock_fips(Handle, buf, (uint)buf.Length));
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

        /* DRBG known-answer health test. Instantiates a temporary DRBG with
         * seedA, optionally reseeds with seedB (reseed = true), generates
         * outputLen bytes twice and returns the second block, for
         * comparison against SP 800-90A test vectors. */
        public static byte[] HealthTest(bool reseed, byte[] seedA, byte[]? seedB, int outputLen)
        {
            if (seedA == null)
                throw new ArgumentNullException(nameof(seedA));
            byte[] output = new byte[outputLen];
            WolfCryptFipsException.Check("wc_RNG_HealthTest_fips",
                Native.wc_RNG_HealthTest_fips(reseed ? 1 : 0, seedA, (uint)seedA.Length,
                    seedB, seedB == null ? 0u : (uint)seedB.Length, output, (uint)outputLen));
            return output;
        }

        protected override void FreeNative()
        {
            if (initialized)
                Native.wc_FreeRng_fips(Handle);
        }
    }
}
