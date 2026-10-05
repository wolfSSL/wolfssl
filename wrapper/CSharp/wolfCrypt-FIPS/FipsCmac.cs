/* FipsCmac.cs
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
    /* CMAC-AES (SP 800-38B). Tags are 8 to 16 bytes (shorter needs a risk analysis,
     * A.2). Per key the caller must use one tag length (5.5) and at most 2^48 messages
     * (App. B). Single use; no module CMAC free, so Dispose zeroes the memory. */
    public sealed class FipsCmac : FipsObject
    {
        private const int WC_CMAC_AES = 1;
        public const int MaxTagSize = 16;
        public const int MinTagSize = 8;
        private bool finished;

        public FipsCmac(byte[] key) : base(FipsStructType.Cmac)
        {
            if (key == null)
            {
                Dispose();
                throw new ArgumentNullException(nameof(key));
            }
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                Dispose();
                throw new ArgumentException("AES key must be 16, 24 or 32 bytes", nameof(key));
            }
            int ret = Native.wc_InitCmac_fips(Handle, key, (uint)key.Length, WC_CMAC_AES, IntPtr.Zero);
            if (ret != 0)
            {
                Dispose();
                throw new WolfCryptFipsException("wc_InitCmac_fips", ret);
            }
        }

        public void Update(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            ThrowIfDisposed();
            if (finished)
            {
                throw new InvalidOperationException("CMAC already finalized");
            }

            WolfCryptFipsException.Check("wc_CmacUpdate_fips",
                Native.wc_CmacUpdate_fips(Handle, data, (uint)data.Length));
        }

        /* Returns a tag of tagSize bytes (8 to 16; shorter tags are the
         * leftmost bytes of the full tag). */
        public byte[] Final(int tagSize = MaxTagSize)
        {
            ThrowIfDisposed();
            if (finished)
            {
                throw new InvalidOperationException("CMAC already finalized");
            }

            if (tagSize < MinTagSize || tagSize > MaxTagSize)
            {
                throw new ArgumentOutOfRangeException(nameof(tagSize));
            }

            byte[] tag = new byte[tagSize];
            uint sz = (uint)tagSize;
            int ret = Native.wc_CmacFinal_fips(Handle, tag, ref sz);
            /* single use whatever the result: the module may have cleared the state */
            finished = true;
            WolfCryptFipsException.Check("wc_CmacFinal_fips", ret);
            if (sz != tag.Length)
            {
                Array.Resize(ref tag, (int)sz);
            }

            return tag;
        }

        public static byte[] Compute(byte[] key, byte[] data, int tagSize = MaxTagSize)
        {
            using var c = new FipsCmac(key);
            c.Update(data);
            return c.Final(tagSize);
        }
    }
}
