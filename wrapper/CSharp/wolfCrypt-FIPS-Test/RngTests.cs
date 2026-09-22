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
        /* SHA-256 Hash_DRBG vectors from wolfcrypt/test/test.c random_test()
         * (NIST CAVP Hash_DRBG.rsp). */
        private const string Test1Entropy =
            "A65AD0F345DB4E0EFFE875C3A2E71F42C7129D620FF5C119A9EF55F05185E0FB8581F9317517276E06E9607DDBCBCC2E";
        private const string Test1Output =
            "D3E160C35B99F340B2628264D1751060E0045DA383FF57A57D73A673D2B8D80DAAF6A6C35A91BB4579D73FD0C8FED111"
          + "B0391306828ADFED528F018121B3FEBDC343E797B87DBB63DB1333DED9D1ECE177CFA6B71FE8AB1DA46624ED6415E51C"
          + "CDE2C7CA86E283990EEAEB91120415528B2295910281B02DD431F4C9F70427DF";
        private const string Test2EntropyA =
            "63363377E41E86468DEB0AB4A8ED683F6A134E47E014C700454E81E95358A569808AA38F2A72A62359915A9F8A04CA68";
        private const string Test2EntropyB =
            "E62B8A8EE8F141B6980566E3BFE3C04903DAD4AC2CDF9F2280010A6739BC83D3";
        private const string Test2Output =
            "04EEC63BB231DF2C630A1AFBE724949D005A587851E1AA795E477347C8B056621C18BDDCDD8D99FC5FC2B92053D8CFAC"
          + "FB0BB8831205FAD1DDD6C071318A6018F03B73F5EDE4D4D071F9DE03FD7AEA105D9299B8AF99AA075BDB4DB9AA28C18D"
          + "174B56EE2A014D098896FF2282C955A81969E069FA8CE007A180183A07DFAE17";

        public static void Run()
        {
            T.Section("Hash_DRBG");

            T.Run("health test KAT, no reseed", () => {
                byte[] outp = FipsRng.HealthTest(false, T.Hex(Test1Entropy), null, 128);
                T.Bytes(T.Hex(Test1Output), outp, "output");
            });

            T.Run("health test KAT, with reseed", () => {
                byte[] outp = FipsRng.HealthTest(true, T.Hex(Test2EntropyA), T.Hex(Test2EntropyB), 128);
                T.Bytes(T.Hex(Test2Output), outp, "output");
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
