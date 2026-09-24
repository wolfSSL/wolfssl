/* RngTests.cs
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

namespace wolfSSL.CSharp.Fips.Test
{
    internal static class RngTests
    {
        public static void Run()
        {
            T.Section("Hash_DRBG");

            /* ACVP hashDRBG (aegisolve). The module's health-test service
             * runs the SP 800-90A instantiate / reseed / generate / generate
             * sequence the vectors describe, returning the second generate. */
            T.Run("ACVP hashDRBG vectors", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("hashDRBG")) {
                    foreach (var g in set.Groups) {
                        T.Equal("SHA2-256", g.GetProperty("mode").GetString(), "mode");
                        T.True(g.GetProperty("persoStringLen").GetInt32() == 0 &&
                               g.GetProperty("additionalInputLen").GetInt32() == 0 &&
                               !g.GetProperty("predResistance").GetBoolean(),
                               "group parameters outside health-test service");
                        bool reseed = g.GetProperty("reSeed").GetBoolean();
                        int outLen = g.GetProperty("returnedBitsLen").GetInt32() / 8;
                        T.Equal(FipsRng.HealthTestOutputSize, outLen, "returnedBitsLen outside health-test service");
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            byte[] seedA = Acvp.Hex(t, "entropyInput").Concat(Acvp.Hex(t, "nonce")).ToArray();
                            byte[]? seedB = null;
                            foreach (var oi in t.GetProperty("otherInput").EnumerateArray())
                                if (oi.GetProperty("intendedUse").GetString() == "reSeed")
                                    seedB = Acvp.Hex(oi, "entropyInput");
                            byte[] got = FipsRng.HealthTest(reseed, seedA, seedB, outLen);
                            T.Bytes(Acvp.Hex(set.ExpectedFor(g, t), "returnedBits"), got,
                                    set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                            n++;
                        }
                    }
                }
                Console.WriteLine("        " + n + " vectors");
            });

            T.Run("HealthTest argument contract (128-byte output, seedB with reseed)", () => {
                byte[] seed = new byte[48];
                foreach (int len in new[] { 64, 127, 129, -1 }) {
                    bool threw = false;
                    try { FipsRng.HealthTest(false, seed, null, len); } catch (ArgumentOutOfRangeException) { threw = true; }
                    T.True(threw, "outputLen " + len + " accepted");
                }
                bool threwB = false;
                try { FipsRng.HealthTest(true, seed, null); } catch (ArgumentNullException) { threwB = true; }
                T.True(threwB, "reseed without seedB accepted");
                T.Equal(128, FipsRng.HealthTest(false, seed, null).Length, "default length");
            });

            T.Run("instantiate, generate, output is not constant", () => {
                using var rng = new FipsRng();
                byte[] a = rng.Generate(64);
                byte[] b = rng.Generate(64);
                T.True(a.Any(x => x != 0), "all-zero output");
                T.True(!a.SequenceEqual(b), "repeated output");
            });

            T.Run("independent instances produce different output", () => {
                using var r1 = new FipsRng();
                using var r2 = new FipsRng();
                T.True(!r1.Generate(32).SequenceEqual(r2.Generate(32)), "same output");
            });

            T.Run("instantiate with nonce", () => {
                using var rng = new FipsRng(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
                T.Equal(48, rng.Generate(48).Length, "length");
            });

            T.Run("maximum request size succeeds", () => {
                using var rng = new FipsRng();
                T.Equal(FipsRng.MaxRequest, rng.Generate(FipsRng.MaxRequest).Length, "length");
            });

            T.Run("request above maximum is rejected by the module", () => {
                using var rng = new FipsRng();
                bool threw = false;
                try { rng.Generate(FipsRng.MaxRequest + 1); }
                catch (WolfCryptFipsException) { threw = true; }
                T.True(threw, "oversized request accepted");
            });

            T.Run("many sequential generates", () => {
                using var rng = new FipsRng();
                for (int i = 0; i < 1000; i++)
                    rng.Generate(32);
            });

            T.Run("use after Dispose throws ObjectDisposedException", () => {
                var rng = new FipsRng();
                rng.Dispose();
                bool threw = false;
                try { rng.Generate(16); }
                catch (ObjectDisposedException) { threw = true; }
                T.True(threw, "no ObjectDisposedException");
            });
        }
    }
}
