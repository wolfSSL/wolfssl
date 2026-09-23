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
using System.Security.Cryptography;

namespace wolfSSL.CSharp.Fips
{
    /* CMAC-AES (SP 800-38B) from the FIPS module. Tags are 8 to 16 bytes:
     * tags under 64 bits need a separate risk analysis (SP 800-38B A.2) and
     * are not offered. Single use: create a new
     * instance per message. The v5.2.3 boundary has no CMAC free routine;
     * the object's memory is zeroed and released on Dispose. */
    public sealed class FipsCmac : FipsObject
    {
        private const int WC_CMAC_AES = 1;
        public const int MaxTagSize = 16;
        public const int MinTagSize = 8;
        private bool finished;

        public FipsCmac(byte[] key) : base(FipsStructType.Cmac)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            int ret = Native.wc_InitCmac_fips(Handle, key, (uint)key.Length, WC_CMAC_AES, IntPtr.Zero);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_InitCmac_fips", ret);
            }
        }

        public void Update(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            ThrowIfDisposed();
            if (finished)
                throw new InvalidOperationException("CMAC already finalized");
            WolfCryptFipsException.Check("wc_CmacUpdate_fips",
                Native.wc_CmacUpdate_fips(Handle, data, (uint)data.Length));
        }

        /* Returns a tag of tagSize bytes (8 to 16; shorter tags are the
         * leftmost bytes of the full tag). */
        public byte[] Final(int tagSize = MaxTagSize)
        {
            ThrowIfDisposed();
            if (finished)
                throw new InvalidOperationException("CMAC already finalized");
            if (tagSize < MinTagSize || tagSize > MaxTagSize)
                throw new ArgumentOutOfRangeException(nameof(tagSize));
            byte[] tag = new byte[tagSize];
            uint sz = (uint)tagSize;
            WolfCryptFipsException.Check("wc_CmacFinal_fips", Native.wc_CmacFinal_fips(Handle, tag, ref sz));
            finished = true;
            if (sz != tag.Length)
                Array.Resize(ref tag, (int)sz);
            return tag;
        }

        public static byte[] Compute(byte[] key, byte[] data, int tagSize = MaxTagSize)
        {
            using var c = new FipsCmac(key);
            c.Update(data);
            return c.Final(tagSize);
        }

        /* Recomputes the tag and compares it in constant time. */
        public static bool Verify(byte[] key, byte[] data, byte[] tag)
        {
            if (tag == null)
                throw new ArgumentNullException(nameof(tag));
            if (tag.Length < MinTagSize || tag.Length > MaxTagSize)
                throw new ArgumentOutOfRangeException(nameof(tag), "CMAC tag must be 8 to 16 bytes");
            byte[] expected = Compute(key, data, tag.Length);
            return CryptographicOperations.FixedTimeEquals(expected, tag);
        }

        protected override void FreeNative()
        {
            /* no wc_CmacFree in the v5.2.3 boundary */
        }
    }
}
