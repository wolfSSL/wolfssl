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
        private static readonly (string acvp, FipsHashType type)[] Hashes = {
            ("SHA-1", FipsHashType.Sha1), ("SHA2-224", FipsHashType.Sha224),
            ("SHA2-256", FipsHashType.Sha256), ("SHA2-384", FipsHashType.Sha384),
            ("SHA2-512", FipsHashType.Sha512), ("SHA3-224", FipsHashType.Sha3_224),
            ("SHA3-256", FipsHashType.Sha3_256), ("SHA3-384", FipsHashType.Sha3_384),
            ("SHA3-512", FipsHashType.Sha3_512)
        };

        public static void Run()
        {
            T.Section("SHA-1 / SHA-2 / SHA-3");

            foreach (var (acvp, type) in Hashes)
                T.Run("ACVP " + acvp + " (AFT + MCT)", () => HashVectors(acvp, type));

            T.Run("incremental update equals one-shot, object reusable after Final", () => {
                byte[] msg = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");
                foreach (var (_, type) in Hashes) {
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

            foreach (var (acvp, type) in Hashes)
                T.Run("ACVP HMAC-" + acvp, () => HmacVectors("HMAC-" + acvp, type));

            T.Run("HMAC key below 112 bits is rejected (HMAC_MIN_KEYLEN_E)", () => {
                T.Throws(FipsError.HMAC_MIN_KEYLEN_E,
                    () => FipsHmac.Compute(FipsHashType.Sha256, new byte[13], new byte[] { 1 }),
                    "13-byte key");
            });

            T.Run("HMAC object reusable after Final", () => {
                byte[] key = new byte[32];
                using var h = new FipsHmac(FipsHashType.Sha256, key);
                h.Update(new byte[] { 1, 2, 3 });
                byte[] a = h.Final();
                h.Update(new byte[] { 1, 2, 3 });
                T.Bytes(a, h.Final(), "second MAC");
            });

            T.Section("CMAC-AES");

            T.Run("ACVP CMAC-AES (gen + ver)", CmacVectors);

            T.Run("CMAC tags below 64 bits are refused", () => {
                bool threw = false;
                try { FipsCmac.Compute(new byte[16], new byte[1], 4); } catch (ArgumentOutOfRangeException) { threw = true; }
                T.True(threw, "4-byte tag generated");
            });

            T.Run("HMAC keys at most 1024 bits; AES-CMAC key sizes", () => {
                byte[] msg = { 1, 2, 3 };
                T.Equal(32, FipsHmac.Compute(FipsHashType.Sha256, new byte[128], msg).Length, "128-byte key");
                bool threw = false;
                try { FipsHmac.Compute(FipsHashType.Sha256, new byte[129], msg); } catch (ArgumentException) { threw = true; }
                T.True(threw, "129-byte key accepted");
                threw = false;
                try { new FipsCmac(new byte[20]).Dispose(); } catch (ArgumentException) { threw = true; }
                T.True(threw, "20-byte CMAC key accepted");
            });

            T.Run("CMAC is single use", () => {
                using var c = new FipsCmac(new byte[16]);
                c.Final();
                bool threw = false;
                try { c.Update(new byte[1]); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "update after final allowed");
            });
        }

        private static void HashVectors(string alg, FipsHashType type)
        {
            int n = 0;
            bool sha3 = alg.StartsWith("SHA3");
            foreach (AcvpVectorSet set in Acvp.Load(alg)) {
                foreach (var g in set.Groups) {
                    string tt = g.GetProperty("testType").GetString()!;
                    foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] msg = Acvp.Hex(t, "msg");
                        if (tt == "AFT") {
                            T.Bytes(Acvp.Hex(exp, "md"), FipsHash.Compute(type, msg), where);
                        }
                        else if (tt == "MCT") {
                            var results = exp.GetProperty("resultsArray").EnumerateArray().ToList();
                            byte[] seed = msg;
                            using var h = new FipsHash(type);
                            for (int j = 0; j < 100; j++) {
                                if (sha3) {
                                    /* SHA-3 MCT: MD(i) = SHA3(MD(i-1)), 1000 times */
                                    for (int i = 0; i < 1000; i++) {
                                        h.Update(seed);
                                        seed = h.Final();
                                    }
                                }
                                else {
                                    /* SHA-1/2 MCT: M(i) = MD(i-3)||MD(i-2)||MD(i-1) */
                                    byte[] a = seed, b = seed, c = seed;
                                    for (int i = 3; i < 1003; i++) {
                                        h.Update(c.Concat(b).Concat(a).ToArray());
                                        c = b; b = a; a = h.Final();
                                    }
                                    seed = a;
                                }
                                T.Bytes(Acvp.Hex(results[j], "md"), seed, where + " MCT j=" + j);
                            }
                        }
                        else {
                            throw new Exception("unhandled test type " + tt);
                        }
                        n++;
                    }
                }
            }
            Console.WriteLine("        " + alg + ": " + n + " vectors");
        }

        private static void HmacVectors(string alg, FipsHashType type)
        {
            int n = 0;
            foreach (AcvpVectorSet set in Acvp.Load(alg)) {
                foreach (var g in set.Groups) {
                    int macLen = g.GetProperty("macLen").GetInt32() / 8;
                    foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                        byte[] mac = FipsHmac.Compute(type, Acvp.Hex(t, "key"), Acvp.Hex(t, "msg"));
                        T.Bytes(Acvp.Hex(set.ExpectedFor(g, t), "mac"), mac.Take(macLen).ToArray(),
                                set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                        n++;
                    }
                }
            }
            Console.WriteLine("        " + alg + ": " + n + " vectors");
        }

        private static void CmacVectors()
        {
            int gen = 0, ver = 0, shortTag = 0;
            foreach (AcvpVectorSet set in Acvp.Load("CMAC-AES")) {
                foreach (var g in set.Groups) {
                    int macLen = g.GetProperty("macLen").GetInt32() / 8;
                    string dir = g.GetProperty("direction").GetString()!;
                    foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key"), msg = Acvp.Hex(t, "message");
                        if (macLen < FipsCmac.MinTagSize) {
                            /* tags under 64 bits are not offered (SP 800-38B A.2) */
                            bool refused = false;
                            try {
                                FipsCmac.Compute(key, msg, macLen);
                            }
                            catch (ArgumentOutOfRangeException) { refused = true; }
                            T.True(refused, where + " short CMAC tag accepted");
                            shortTag++;
                            continue;
                        }
                        if (dir == "gen") {
                            T.Bytes(Acvp.Hex(exp, "mac"), FipsCmac.Compute(key, msg, macLen), where);
                            gen++;
                        }
                        else {
                            /* verification: the boundary generates; the test compares */
                            T.Equal(exp.GetProperty("testPassed").GetBoolean(),
                                    FipsCmac.Compute(key, msg, macLen).SequenceEqual(Acvp.Hex(t, "mac")), where);
                            ver++;
                        }
                    }
                }
            }
            Console.WriteLine("        CMAC-AES: " + gen + " gen, " + ver + " ver, " + shortTag + " sub-64-bit tag refused");
        }
    }
}
