/* FipsHash.cs
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
    /* Approved hash algorithms in the v5.2.3 module. Values are the module's
     * wc_HashType values (v5 numbering, wolfssl/wolfcrypt/types.h), which
     * are also the HMAC type identifiers. */
    public enum FipsHashType
    {
        Sha1 = 4,
        Sha224 = 5,
        Sha256 = 6,
        Sha384 = 7,
        Sha512 = 8,
        Sha3_224 = 10,
        Sha3_256 = 11,
        Sha3_384 = 12,
        Sha3_512 = 13
    }

    /* Incremental message digest (SHA-1, SHA-2, SHA-3) from the FIPS module.
     * After Final the object is reset and can hash a new message. */
    public sealed class FipsHash : FipsObject
    {
        private const int INVALID_DEVID = -2;

        public FipsHashType Type { get; }
        public int DigestSize => DigestSizeOf(Type);

        public FipsHash(FipsHashType type) : base(StructOf(type))
        {
            Type = type;
            int ret = Init(type, Handle);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_Init" + type + "_fips", ret);
            }
            initialized = true;
        }

        private bool initialized;

        public void Update(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            ThrowIfDisposed();
            WolfCryptFipsException.Check(Type + " update", Update(Type, Handle, data, (uint)data.Length));
        }

        /* Returns the digest and resets the object for a new message. */
        public byte[] Final()
        {
            ThrowIfDisposed();
            byte[] digest = new byte[DigestSize];
            WolfCryptFipsException.Check(Type + " final", Final(Type, Handle, digest));
            return digest;
        }

        /* One-shot digest of data. */
        public static byte[] Compute(FipsHashType type, byte[] data)
        {
            using var h = new FipsHash(type);
            h.Update(data);
            return h.Final();
        }

        public static int DigestSizeOf(FipsHashType type) => type switch {
            FipsHashType.Sha1 => 20,
            FipsHashType.Sha224 or FipsHashType.Sha3_224 => 28,
            FipsHashType.Sha256 or FipsHashType.Sha3_256 => 32,
            FipsHashType.Sha384 or FipsHashType.Sha3_384 => 48,
            FipsHashType.Sha512 or FipsHashType.Sha3_512 => 64,
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

        private static FipsStructType StructOf(FipsHashType type) => type switch {
            FipsHashType.Sha1 => FipsStructType.Sha,
            FipsHashType.Sha224 => FipsStructType.Sha224,
            FipsHashType.Sha256 => FipsStructType.Sha256,
            FipsHashType.Sha384 => FipsStructType.Sha384,
            FipsHashType.Sha512 => FipsStructType.Sha512,
            FipsHashType.Sha3_224 or FipsHashType.Sha3_256 or
            FipsHashType.Sha3_384 or FipsHashType.Sha3_512 => FipsStructType.Sha3,
            _ => throw new ArgumentOutOfRangeException(nameof(type))
        };

        private static int Init(FipsHashType t, IntPtr h)
        {
            switch (t) {
                case FipsHashType.Sha1: return Native.wc_InitSha_fips(h);
                case FipsHashType.Sha224: return Native.wc_InitSha224_fips(h);
                case FipsHashType.Sha256: return Native.wc_InitSha256_fips(h);
                case FipsHashType.Sha384: return Native.wc_InitSha384_fips(h);
                case FipsHashType.Sha512: return Native.wc_InitSha512_fips(h);
                case FipsHashType.Sha3_224: return Native.wc_InitSha3_224_fips(h, IntPtr.Zero, INVALID_DEVID);
                case FipsHashType.Sha3_256: return Native.wc_InitSha3_256_fips(h, IntPtr.Zero, INVALID_DEVID);
                case FipsHashType.Sha3_384: return Native.wc_InitSha3_384_fips(h, IntPtr.Zero, INVALID_DEVID);
                case FipsHashType.Sha3_512: return Native.wc_InitSha3_512_fips(h, IntPtr.Zero, INVALID_DEVID);
                default: throw new ArgumentOutOfRangeException(nameof(t));
            }
        }

        private static int Update(FipsHashType t, IntPtr h, byte[] d, uint len)
        {
            switch (t) {
                case FipsHashType.Sha1: return Native.wc_ShaUpdate_fips(h, d, len);
                case FipsHashType.Sha224: return Native.wc_Sha224Update_fips(h, d, len);
                case FipsHashType.Sha256: return Native.wc_Sha256Update_fips(h, d, len);
                case FipsHashType.Sha384: return Native.wc_Sha384Update_fips(h, d, len);
                case FipsHashType.Sha512: return Native.wc_Sha512Update_fips(h, d, len);
                case FipsHashType.Sha3_224: return Native.wc_Sha3_224_Update_fips(h, d, len);
                case FipsHashType.Sha3_256: return Native.wc_Sha3_256_Update_fips(h, d, len);
                case FipsHashType.Sha3_384: return Native.wc_Sha3_384_Update_fips(h, d, len);
                case FipsHashType.Sha3_512: return Native.wc_Sha3_512_Update_fips(h, d, len);
                default: throw new ArgumentOutOfRangeException(nameof(t));
            }
        }

        private static int Final(FipsHashType t, IntPtr h, byte[] o)
        {
            switch (t) {
                case FipsHashType.Sha1: return Native.wc_ShaFinal_fips(h, o);
                case FipsHashType.Sha224: return Native.wc_Sha224Final_fips(h, o);
                case FipsHashType.Sha256: return Native.wc_Sha256Final_fips(h, o);
                case FipsHashType.Sha384: return Native.wc_Sha384Final_fips(h, o);
                case FipsHashType.Sha512: return Native.wc_Sha512Final_fips(h, o);
                case FipsHashType.Sha3_224: return Native.wc_Sha3_224_Final_fips(h, o);
                case FipsHashType.Sha3_256: return Native.wc_Sha3_256_Final_fips(h, o);
                case FipsHashType.Sha3_384: return Native.wc_Sha3_384_Final_fips(h, o);
                case FipsHashType.Sha3_512: return Native.wc_Sha3_512_Final_fips(h, o);
                default: throw new ArgumentOutOfRangeException(nameof(t));
            }
        }

        protected override void FreeNative()
        {
            if (!initialized)
                return;
            IntPtr h = Handle;
            switch (Type) {
                case FipsHashType.Sha1: Native.wc_ShaFree_fips(h); break;
                case FipsHashType.Sha224: Native.wc_Sha224Free_fips(h); break;
                case FipsHashType.Sha256: Native.wc_Sha256Free_fips(h); break;
                case FipsHashType.Sha384: Native.wc_Sha384Free_fips(h); break;
                case FipsHashType.Sha512: Native.wc_Sha512Free_fips(h); break;
                case FipsHashType.Sha3_224: Native.wc_Sha3_224_Free_fips(h); break;
                case FipsHashType.Sha3_256: Native.wc_Sha3_256_Free_fips(h); break;
                case FipsHashType.Sha3_384: Native.wc_Sha3_384_Free_fips(h); break;
                case FipsHashType.Sha3_512: Native.wc_Sha3_512_Free_fips(h); break;
            }
        }
    }
}
