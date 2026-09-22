/* FipsHmac.cs
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
    /* HMAC (FIPS 198-1) from the FIPS module. The module enforces a minimum
     * key length of 112 bits (HMAC_MIN_KEYLEN_E). After Final the object is
     * reset to the keyed state and can authenticate a new message. */
    public sealed class FipsHmac : FipsObject
    {
        public FipsHashType Type { get; }
        public int MacSize => FipsHash.DigestSizeOf(Type);
        private bool keyed;

        public FipsHmac(FipsHashType type, byte[] key) : base(FipsStructType.Hmac)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            Type = type;
            int ret = Native.wc_HmacSetKey_fips(Handle, (int)type, key, (uint)key.Length);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_HmacSetKey_fips", ret);
            }
            keyed = true;
        }

        public void Update(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            ThrowIfDisposed();
            WolfCryptFipsException.Check("wc_HmacUpdate_fips",
                Native.wc_HmacUpdate_fips(Handle, data, (uint)data.Length));
        }

        public byte[] Final()
        {
            ThrowIfDisposed();
            byte[] mac = new byte[MacSize];
            WolfCryptFipsException.Check("wc_HmacFinal_fips", Native.wc_HmacFinal_fips(Handle, mac));
            return mac;
        }

        public static byte[] Compute(FipsHashType type, byte[] key, byte[] data)
        {
            using var h = new FipsHmac(type, key);
            h.Update(data);
            return h.Final();
        }

        protected override void FreeNative()
        {
            if (keyed)
                Native.wc_HmacFree_fips(Handle);
        }
    }
}
