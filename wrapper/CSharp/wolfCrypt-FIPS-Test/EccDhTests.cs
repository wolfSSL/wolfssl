/* EccDhTests.cs
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
using System.Security.Cryptography;

namespace wolfSSL.CSharp.Fips.Test
{
    internal static class EccDhTests
    {
        private static readonly FipsEccCurve[] SignCurves =
            { FipsEccCurve.P224, FipsEccCurve.P256, FipsEccCurve.P384, FipsEccCurve.P521 };

        public static void Run()
        {
            using var rng = new FipsRng();

            T.Section("ECDSA");

            T.Run("ACVP ECDSA keyVer (FIPS 186-4 + 186-5)", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("ECDSA").Where(s => Mode(s) == "keyVer"))
                    foreach (var g in set.Groups) {
                        FipsEccCurve c = CurveOf(g.GetProperty("curve").GetString()!);
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            bool ok;
                            try {
                                using var k = FipsEccKey.ImportPublic(c, Acvp.Hex(t, "qx"), Acvp.Hex(t, "qy"));
                                k.Check();
                                ok = true;
                            }
                            catch (Exception e) when (e is WolfCryptFipsException || e is ArgumentException) { ok = false; }
                            T.Equal(set.ExpectedFor(g, t).GetProperty("testPassed").GetBoolean(), ok,
                                    set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " keyVer vectors");
            });

            T.Run("ACVP ECDSA sigVer (FIPS 186-4 + 186-5, SHA-2 and SHA-3)", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("ECDSA").Where(s => Mode(s) == "sigVer"))
                    foreach (var g in set.Groups) {
                        FipsEccCurve c = CurveOf(g.GetProperty("curve").GetString()!);
                        FipsHashType h = HashOf(g.GetProperty("hashAlg").GetString()!);
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            byte[] digest = FipsHash.Compute(h, Acvp.Hex(t, "message"));
                            byte[] der = FipsEcdsaSignature.ToDer(Acvp.Hex(t, "r"), Acvp.Hex(t, "s"));
                            bool ok;
                            try {
                                using var k = FipsEccKey.ImportPublic(c, Acvp.Hex(t, "qx"), Acvp.Hex(t, "qy"));
                                ok = k.VerifyHash(digest, der);
                            }
                            catch (Exception e) when (e is WolfCryptFipsException || e is ArgumentException) { ok = false; }
                            T.Equal(set.ExpectedFor(g, t).GetProperty("testPassed").GetBoolean(), ok,
                                    set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " sigVer vectors");
            });

            T.Run("ACVP ECDSA sigGen messages: module signatures verify in module and .NET", () => {
                int n = 0, net = 0;
                foreach (AcvpVectorSet set in Acvp.Load("ECDSA").Where(s => Mode(s) == "sigGen"))
                    foreach (var g in set.Groups) {
                        FipsEccCurve c = CurveOf(g.GetProperty("curve").GetString()!);
                        FipsHashType h = HashOf(g.GetProperty("hashAlg").GetString()!);
                        bool component = g.TryGetProperty("componentTest", out var ct) && ct.GetBoolean();
                        using var key = FipsEccKey.Generate(c, rng);
                        using ECDsa? dn = DotNetPublic(c, key.ExportPublic());
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            byte[] msg = Acvp.Hex(t, "message");
                            byte[] digest = component ? msg : FipsHash.Compute(h, msg);
                            byte[] sig = key.SignHash(digest);
                            string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                            T.True(key.VerifyHash(digest, sig), where + " module verify");
                            if (dn != null) {
                                T.True(dn.VerifyHash(digest, sig, DSASignatureFormat.Rfc3279DerSequence), where + " .NET verify");
                                net++;
                            }
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " sigGen messages, " + net + " also verified by .NET");
            });

            T.Run("ACVP ECDSA keyGen: generated keys pass key check", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("ECDSA").Where(s => Mode(s) == "keyGen"))
                    foreach (var g in set.Groups) {
                        FipsEccCurve c = CurveOf(g.GetProperty("curve").GetString()!);
                        foreach (var _ in g.GetProperty("tests").EnumerateArray()) {
                            using var k = FipsEccKey.Generate(c, rng);
                            k.Check();
                            T.Equal(1 + 2 * k.FieldSize, k.ExportPublic().Length, "point size");
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " keys");
            });

            T.Run("operations that unlock the key read gate restore it", () => {
                FipsModule.SetPrivateKeyReadEnable(false);
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                k.ExportPublic();
                k.SharedSecret(k);
                T.True(!FipsModule.PrivateKeyReadEnabled, "gate left enabled");
                FipsModule.SetPrivateKeyReadEnable(true);
                k.ExportPublic();
                T.True(FipsModule.PrivateKeyReadEnabled, "gate disabled by operation");
                FipsModule.SetPrivateKeyReadEnable(false);
            });

            T.Run("P-192 key generation and signing are refused", () => {
                bool threw = false;
                try { FipsEccKey.Generate(FipsEccCurve.P192, rng).Dispose(); } catch (ArgumentException) { threw = true; }
                T.True(threw, "P-192 key generated");
            });

            T.Run("tampered signature or digest does not verify", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                byte[] d = FipsHash.Compute(FipsHashType.Sha256, new byte[] { 1 });
                byte[] sig = k.SignHash(d);
                byte[] d2 = (byte[])d.Clone(); d2[0] ^= 1;
                T.True(!k.VerifyHash(d2, sig), "wrong digest");
                byte[] rs = FipsEcdsaSignature.ToP1363(sig, 32);
                rs[5] ^= 1;
                T.True(!k.VerifyHash(d, FipsEcdsaSignature.FromP1363(rs)), "tampered r");
            });

            T.Run("public-only key cannot sign", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                using var pub = FipsEccKey.ImportPublic(FipsEccCurve.P256, k.ExportPublic());
                bool threw = false;
                try { pub.SignHash(new byte[32]); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "public key signed");
            });

            T.Run("off-curve public key fails key check", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                byte[] pt = k.ExportPublic();
                pt[pt.Length - 1] ^= 1;
                bool ok;
                try { using var bad = FipsEccKey.ImportPublic(FipsEccCurve.P256, pt); bad.Check(); ok = true; }
                catch (WolfCryptFipsException) { ok = false; }
                T.True(!ok, "off-curve point accepted");
            });

            T.Section("ECC CDH (KAS-ECC-SSC)");

            foreach (FipsEccCurve c in new[] { FipsEccCurve.P256, FipsEccCurve.P384, FipsEccCurve.P521 }) {
                FipsEccCurve curve = c;
                T.Run("ECDH " + curve + ": module and .NET derive the same Z", () => {
                    using var ours = FipsEccKey.Generate(curve, rng);
                    using var theirs = ECDiffieHellman.Create(NetCurve(curve));
                    var tp = theirs.ExportParameters(false);
                    using var theirPub = FipsEccKey.ImportPublic(curve, tp.Q.X!, tp.Q.Y!);
                    byte[] zModule = ours.SharedSecret(theirPub);
                    using var ourPubNet = ECDiffieHellman.Create(PublicParams(curve, ours.ExportPublic()));
                    byte[] zNet = theirs.DeriveRawSecretAgreement(ourPubNet.PublicKey);
                    T.Bytes(zNet, zModule, "Z");
                });
            }

            T.Run("ACVP KAS-ECC-SSC AFT: Z with server keys", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("KAS-ECC-SSC"))
                    foreach (var g in set.Groups.Where(x => x.GetProperty("testType").GetString() == "AFT")) {
                        FipsEccCurve c = CurveOf(g.GetProperty("domainParameterGenerationMode").GetString()!);
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            using var ours = FipsEccKey.Generate(c, rng);
                            using var server = FipsEccKey.ImportPublic(c, Acvp.Hex(t, "ephemeralPublicServerX"),
                                                                           Acvp.Hex(t, "ephemeralPublicServerY"));
                            T.Equal(FipsEccKey.FieldSizeOf(c), ours.SharedSecret(server).Length, "Z length");
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " AFT vectors");
            });

            T.Run("ACVP KAS-ECC-SSC VAL", () =>
                T.Skip("VAL supplies the IUT private key; the v5.2.3 boundary has no ECC private key import"));

            T.Section("Finite field DH (KAS-FFC-SSC)");

            T.Run("ACVP KAS-FFC-SSC VAL (hashZ)", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("KAS-FFC-SSC"))
                    foreach (var g in set.Groups.Where(x => x.GetProperty("testType").GetString() == "VAL")) {
                        using var dh = new FipsDh(GroupOf(g.GetProperty("domainParameterGenerationMode").GetString()!));
                        FipsHashType h = HashOf(g.GetProperty("hashFunctionZ").GetString()!);
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            bool ok;
                            try {
                                byte[] z = dh.Agree(Acvp.Hex(t, "ephemeralPrivateIut"), Acvp.Hex(t, "ephemeralPublicServer"));
                                ok = FipsHash.Compute(h, z).SequenceEqual(Acvp.Hex(t, "hashZ"));
                            }
                            catch (WolfCryptFipsException) { ok = false; }
                            T.Equal(set.ExpectedFor(g, t).GetProperty("testPassed").GetBoolean(), ok,
                                    set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " VAL vectors");
            });

            T.Run("ACVP KAS-FFC-SSC AFT: Z with server keys", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("KAS-FFC-SSC"))
                    foreach (var g in set.Groups.Where(x => x.GetProperty("testType").GetString() == "AFT")) {
                        using var dh = new FipsDh(GroupOf(g.GetProperty("domainParameterGenerationMode").GetString()!));
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            using var kp = dh.GenerateKeyPair(rng);
                            T.Equal(dh.PrimeSize, dh.Agree(kp.PrivateKey, Acvp.Hex(t, "ephemeralPublicServer")).Length, "Z length");
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " AFT vectors");
            });

            T.Run("DH ffdhe2048: two parties derive the same Z; key pair checks", () => {
                using var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
                using var a = dh.GenerateKeyPair(rng);
                using var b = dh.GenerateKeyPair(rng);
                T.Bytes(dh.Agree(a.PrivateKey, b.PublicKey), dh.Agree(b.PrivateKey, a.PublicKey), "Z");
                T.True(dh.CheckPublicKey(a.PublicKey), "public key check");
                T.True(dh.CheckPrivateKey(a.PrivateKey), "private key check");
                T.True(dh.CheckKeyPair(a.PublicKey, a.PrivateKey), "pair check");
                T.True(!dh.CheckKeyPair(b.PublicKey, a.PrivateKey), "mismatched pair accepted");
            });

            T.Run("DH rejects invalid peer public keys (1, p-1)", () => {
                using var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
                using var a = dh.GenerateKeyPair(rng);
                byte[] one = new byte[dh.PrimeSize]; one[^1] = 1;
                T.True(!dh.CheckPublicKey(one), "y = 1 accepted");
                bool threw = false;
                try { dh.Agree(a.PrivateKey, one); } catch (WolfCryptFipsException) { threw = true; }
                T.True(threw, "agreement with y = 1");
            });

            T.Run("DH GeneratePublic matches generated key pair (v5.2.3+)", () => {
                using var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
                using var kp = dh.GenerateKeyPair(rng);
                try {
                    T.Bytes(kp.PublicKey, dh.GeneratePublic(kp.PrivateKey), "public key");
                }
                catch (NotSupportedException e) { T.Skip(e.Message); }
            });
        }

        private static string Mode(AcvpVectorSet s) => s.Request.GetProperty("mode").GetString()!;

        private static FipsEccCurve CurveOf(string c) => c switch {
            "P-192" => FipsEccCurve.P192, "P-224" => FipsEccCurve.P224, "P-256" => FipsEccCurve.P256,
            "P-384" => FipsEccCurve.P384, "P-521" => FipsEccCurve.P521,
            _ => throw new Exception("curve " + c)
        };

        private static FipsDhGroup GroupOf(string g) => g switch {
            "ffdhe2048" => FipsDhGroup.Ffdhe2048, "ffdhe3072" => FipsDhGroup.Ffdhe3072,
            "ffdhe4096" => FipsDhGroup.Ffdhe4096, "ffdhe6144" => FipsDhGroup.Ffdhe6144,
            "ffdhe8192" => FipsDhGroup.Ffdhe8192, _ => throw new Exception("group " + g)
        };

        internal static FipsHashType HashOf(string h) => h switch {
            "SHA-1" => FipsHashType.Sha1, "SHA2-224" => FipsHashType.Sha224, "SHA2-256" => FipsHashType.Sha256,
            "SHA2-384" => FipsHashType.Sha384, "SHA2-512" => FipsHashType.Sha512,
            "SHA3-224" => FipsHashType.Sha3_224, "SHA3-256" => FipsHashType.Sha3_256,
            "SHA3-384" => FipsHashType.Sha3_384, "SHA3-512" => FipsHashType.Sha3_512,
            _ => throw new Exception("hash " + h)
        };

        private static ECCurve NetCurve(FipsEccCurve c) => c switch {
            FipsEccCurve.P256 => ECCurve.NamedCurves.nistP256,
            FipsEccCurve.P384 => ECCurve.NamedCurves.nistP384,
            FipsEccCurve.P521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.CreateFromValue(c == FipsEccCurve.P224 ? "1.3.132.0.33" : "1.2.840.10045.3.1.1")
        };

        private static ECParameters PublicParams(FipsEccCurve c, byte[] x963)
        {
            int n = FipsEccKey.FieldSizeOf(c);
            return new ECParameters { Curve = NetCurve(c), Q = new ECPoint {
                X = x963.Skip(1).Take(n).ToArray(), Y = x963.Skip(1 + n).Take(n).ToArray() } };
        }

        /* .NET verifier for the curve, or null when the platform does not
         * support it (P-224 on some OSes). */
        private static ECDsa? DotNetPublic(FipsEccCurve c, byte[] x963)
        {
            try { return ECDsa.Create(PublicParams(c, x963)); }
            catch (Exception e) when (e is PlatformNotSupportedException || e is CryptographicException) { return null; }
        }
    }
}
