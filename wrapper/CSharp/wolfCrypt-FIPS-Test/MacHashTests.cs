/* MacHashTests.cs
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
using System.Linq;
using System.Text;

namespace wolfSSL.CSharp.Fips.Test
{
    internal static class MacHashTests
    {
        private static readonly FipsHashType[] Hashes = {
            FipsHashType.Sha1, FipsHashType.Sha224, FipsHashType.Sha256, FipsHashType.Sha384,
            FipsHashType.Sha512, FipsHashType.Sha3_224, FipsHashType.Sha3_256, FipsHashType.Sha3_384,
            FipsHashType.Sha3_512
        };

        public static void Run()
        {
            T.Section("SHA-1 / SHA-2 / SHA-3");

            T.Run("incremental update equals one-shot, object reusable after Final", () =>
            {
                byte[] msg = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");
                foreach (FipsHashType type in Hashes)
                {
                    using var h = new FipsHash(type);
                    h.Update(msg.Take(10).ToArray());
                    h.Update(msg.Skip(10).ToArray());
                    byte[] a = h.Final();
                    T.Bytes(FipsHash.Compute(type, msg), a, type + " incremental");
                    h.Update(msg);
                    T.Bytes(a, h.Final(), type + " reuse");
                }
            });

            T.Section("HMAC");

            T.Run("HMAC key below 112 bits is rejected (HMAC_MIN_KEYLEN_E)", () =>
            {
                T.Throws(FipsError.HMAC_MIN_KEYLEN_E,
                    () => FipsHmac.Compute(FipsHashType.Sha256, new byte[13], new byte[] { 1 }),
                    "13-byte key");
            });

            T.Run("HMAC object reusable after Final", () =>
            {
                byte[] key = new byte[32];
                using var h = new FipsHmac(FipsHashType.Sha256, key);
                h.Update(new byte[] { 1, 2, 3 });
                byte[] a = h.Final();
                h.Update(new byte[] { 1, 2, 3 });
                T.Bytes(a, h.Final(), "second MAC");
            });

            T.Section("CMAC-AES");

            T.Run("CMAC tags below 64 bits are refused", () =>
            {
                bool threw = false;
                try { FipsCmac.Compute(new byte[16], new byte[1], 4); } catch (ArgumentOutOfRangeException) { threw = true; }
                T.True(threw, "4-byte tag generated");
            });

            T.Run("HMAC keys at most 1024 bits; AES-CMAC key sizes", () =>
            {
                byte[] msg = { 1, 2, 3 };
                T.Equal(32, FipsHmac.Compute(FipsHashType.Sha256, new byte[128], msg).Length, "128-byte key");
                bool threw = false;
                try { FipsHmac.Compute(FipsHashType.Sha256, new byte[129], msg); } catch (ArgumentException) { threw = true; }
                T.True(threw, "129-byte key accepted");
                threw = false;
                try { new FipsCmac(new byte[20]).Dispose(); } catch (ArgumentException) { threw = true; }
                T.True(threw, "20-byte CMAC key accepted");
            });

            T.Run("CMAC is single use", () =>
            {
                using var c = new FipsCmac(new byte[16]);
                c.Final();
                bool threw = false;
                try { c.Update(new byte[1]); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "update after final allowed");
            });
        }

    }
}
