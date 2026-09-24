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
using System.Numerics;
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
                                using var k = EccTestHelpers.ImportPublic(c, Acvp.Hex(t, "qx"), Acvp.Hex(t, "qy"));
                                k.Check();
                                ok = true;
                            }
                            catch (Exception e) when (e is WolfCryptFipsException || e is ArgumentException) { ok = false; }
                            T.Equal(set.ExpectedFor(g, t).GetProperty("testPassed").GetBoolean(), ok,
                                    set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                            n++;
                        }
                    }
                T.True(n > 0, "no keyVer vectors");
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
                                using var k = EccTestHelpers.ImportPublic(c, Acvp.Hex(t, "qx"), Acvp.Hex(t, "qy"));
                                ok = k.VerifyHash(h, digest, der);
                            }
                            catch (Exception e) when (e is WolfCryptFipsException || e is ArgumentException) { ok = false; }
                            T.Equal(set.ExpectedFor(g, t).GetProperty("testPassed").GetBoolean(), ok,
                                    set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                            n++;
                        }
                    }
                T.True(n > 0, "no sigVer vectors");
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
                            byte[] sig = key.SignHash(h, digest);
                            string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                            T.True(key.VerifyHash(h, digest, sig), where + " module verify");
                            if (dn != null) {
                                T.True(dn.VerifyHash(digest, sig, DSASignatureFormat.Rfc3279DerSequence), where + " .NET verify");
                                net++;
                            }
                            n++;
                        }
                    }
                T.True(n > 0, "no sigGen messages");
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
                T.True(n > 0, "no keys");
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
                byte[] sig = k.SignHash(FipsHashType.Sha256, d);
                byte[] d2 = (byte[])d.Clone(); d2[0] ^= 1;
                T.True(!k.VerifyHash(FipsHashType.Sha256, d2, sig), "wrong digest");
                byte[] rs = FipsEcdsaSignature.ToP1363(sig, 32);
                rs[5] ^= 1;
                T.True(!k.VerifyHash(FipsHashType.Sha256, d, FipsEcdsaSignature.FromP1363(rs)), "tampered r");
            });

            /* CVE-2026-5194 class: the module has no digest length bound, so
             * a short digest must never reach it */
            T.Run("ECDSA verify requires the digest length of the stated hash", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                byte[] sig = k.SignHash(FipsHashType.Sha256, new byte[32]);
                foreach (int len in new[] { 0, 1, 16, 31, 33 }) {
                    bool threw = false;
                    try { k.VerifyHash(FipsHashType.Sha256, new byte[len], sig); } catch (ArgumentException) { threw = true; }
                    T.True(threw, len + "-byte digest accepted as SHA-256");
                }
                T.True(k.VerifyHash(FipsHashType.Sha256, new byte[32], sig), "32-byte digest verifies");
            });

            T.Run("public-only key cannot sign", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                using var pub = FipsEccKey.ImportPublic(FipsEccCurve.P256, k.ExportPublic());
                bool threw = false;
                try { pub.SignHash(FipsHashType.Sha256, new byte[32]); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "public key signed");
            });

            T.Run("ECDSA signing refuses SHA-1 and mismatched digest lengths", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                bool threw = false;
                try { k.SignHash(FipsHashType.Sha1, new byte[20]); } catch (ArgumentException) { threw = true; }
                T.True(threw, "SHA-1 signed");
                threw = false;
                try { k.SignHash(FipsHashType.Sha384, new byte[32]); } catch (ArgumentException) { threw = true; }
                T.True(threw, "32-byte digest accepted as SHA-384");
                T.True(k.VerifyHash(FipsHashType.Sha256, new byte[32], k.SignHash(FipsHashType.Sha256, new byte[32])), "SHA-256 still signs");
            });

            T.Run("key keeps working after the generation DRBG is disposed", () => {
                FipsEccKey k, peer;
                using (var genRng = new FipsRng()) {
                    k = FipsEccKey.Generate(FipsEccCurve.P384, genRng);
                    peer = FipsEccKey.Generate(FipsEccCurve.P384, genRng);
                }
                for (int i = 0; i < 20; i++) {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    k.Check();
                    T.Equal(48, k.SharedSecret(peer).Length, "shared secret");
                    byte[] d = new byte[48];
                    T.True(k.VerifyHash(FipsHashType.Sha384, d, k.SignHash(FipsHashType.Sha384, d)), "sign/verify");
                }
                k.Dispose();
                peer.Dispose();
            });

            T.Run("DER signature parser is strict", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                byte[] good = k.SignHash(FipsHashType.Sha256, new byte[32]);
                var (r, s) = FipsEcdsaSignature.FromDer(good);
                T.Bytes(good, FipsEcdsaSignature.ToDer(r, s), "round trip");
                string? param = null;
                try { FipsEcdsaSignature.ToDer(r, null!); } catch (ArgumentNullException e) { param = e.ParamName; }
                T.Equal("s", param, "null s reported by name");
                param = null;
                try { EccTestHelpers.ImportPublic(FipsEccCurve.P256, null!, new byte[32]).Dispose(); }
                catch (ArgumentNullException e) { param = e.ParamName; }
                T.Equal("x", param, "null x reported by name");
                foreach (var (bad, what) in new[] {
                        (T.Hex("3006020101020201"), "truncated integer"),
                        (good.Concat(new byte[] { 0 }).ToArray(), "trailing data"),
                        (T.Hex("30060201ff020101"), "negative r"),
                        (T.Hex("3007020200010201 01".Replace(" ", "")), "non-minimal r"),
                        (T.Hex("30060201000201 01".Replace(" ", "")), "zero r"),
                        (T.Hex("3081060201010201 01".Replace(" ", "")), "non-minimal length"),
                        (T.Hex("30"), "header only") }) {
                    bool threw = false;
                    try { FipsEcdsaSignature.FromDer(bad); } catch (FormatException) { threw = true; }
                    T.True(threw, what + " accepted");
                }
                bool threwNull = false;
                try { FipsEcdsaSignature.FromDer(null!); } catch (ArgumentNullException) { threwNull = true; }
                T.True(threwNull, "null accepted");
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
                    using var theirPub = EccTestHelpers.ImportPublic(curve, tp.Q.X!, tp.Q.Y!);
                    byte[] zModule = ours.SharedSecret(theirPub);
                    using var ourPubNet = ECDiffieHellman.Create(PublicParams(curve, ours.ExportPublic()));
                    byte[] zNet = theirs.DeriveRawSecretAgreement(ourPubNet.PublicKey);
                    T.Bytes(zNet, zModule, "Z");
                });
            }

            T.Run("ECC CDH refused on P-224 (not a validated KAS-ECC-SSC domain)", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P224, rng);
                using var peer = FipsEccKey.Generate(FipsEccCurve.P224, rng);
                bool threw = false;
                try { k.SharedSecret(peer); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "P-224 CDH performed");
            });

            T.Run("off-curve peer points are refused at import, before any CDH", () => {
                using var k = FipsEccKey.Generate(FipsEccCurve.P256, rng);
                byte[] pt = k.ExportPublic();
                pt[^1] ^= 1;   /* y + 1: off the curve */
                bool threw = false;
                try { FipsEccKey.ImportPublic(FipsEccCurve.P256, pt).Dispose(); }
                catch (WolfCryptFipsException) { threw = true; }
                T.True(threw, "off-curve point imported");
                T.Equal(1, Native.SizeOf((int)FipsStructType.ValidateEccImport),
                        "WOLFSSL_VALIDATE_ECC_IMPORT (module validates on import)");
            });

            T.Run("ACVP KAS-ECC-SSC AFT: Z with server keys", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("KAS-ECC-SSC"))
                    foreach (var g in set.Groups.Where(x => x.GetProperty("testType").GetString() == "AFT")) {
                        FipsEccCurve c = CurveOf(g.GetProperty("domainParameterGenerationMode").GetString()!);
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            using var ours = FipsEccKey.Generate(c, rng);
                            using var server = EccTestHelpers.ImportPublic(c, Acvp.Hex(t, "ephemeralPublicServerX"),
                                                                           Acvp.Hex(t, "ephemeralPublicServerY"));
                            T.Equal(FipsEccKey.FieldSizeOf(c), ours.SharedSecret(server).Length, "Z length");
                            n++;
                        }
                    }
                T.True(n > 0, "no AFT vectors");
                Console.WriteLine("        " + n + " AFT vectors");
            });

            T.Run("ACVP KAS-ECC-SSC VAL", () =>
                T.Skip("VAL supplies the IUT private key; the v5.2.3 boundary has no ECC private key import"));

            T.Section("Finite field DH (KAS-FFC-SSC)");

            T.Run("ACVP KAS-FFC-SSC VAL (hashZ)", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("KAS-FFC-SSC"))
                    foreach (var g in set.Groups.Where(x => x.GetProperty("testType").GetString() == "VAL")) {
                        using var dh = FipsDh.AnyNamedGroup(GroupOf(g.GetProperty("domainParameterGenerationMode").GetString()!));
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
                T.True(n > 0, "no VAL vectors");
                Console.WriteLine("        " + n + " VAL vectors");
            });

            T.Run("ACVP KAS-FFC-SSC AFT: Z with server keys", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("KAS-FFC-SSC"))
                    foreach (var g in set.Groups.Where(x => x.GetProperty("testType").GetString() == "AFT")) {
                        FipsDhGroup grp = GroupOf(g.GetProperty("domainParameterGenerationMode").GetString()!);
                        using var dh = FipsDh.AnyNamedGroup(grp);
                        byte[] p = Ffdhe.P[grp];
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            using var kp = dh.GenerateKeyPair(rng);
                            byte[] ys = Acvp.Hex(t, "ephemeralPublicServer");
                            string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                            T.Bytes(ModPow(ys, kp.PrivateKey, p), dh.Agree(kp.PrivateKey, ys), where + " Z = Ys^x mod p");
                            T.Bytes(ModPow(new byte[] { 2 }, kp.PrivateKey, p), kp.PublicKey, where + " public key = 2^x mod p");
                            n++;
                        }
                    }
                T.True(n > 0, "no AFT vectors");
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

            T.Run("DH explicit domain rejects in-range small-order peer keys (order 7)", () => {
                using var dhx = new FipsDh(Rfc5114P, Rfc5114G, Rfc5114Q);
                using var a = dhx.GenerateKeyPair(rng);
                byte[] y = Rfc5114Order7;
                T.True(!dhx.CheckPublicKey(y), "small-order key passed validation");
                bool threw = false;
                try { dhx.Agree(a.PrivateKey, y); } catch (WolfCryptFipsException) { threw = true; }
                T.True(threw, "agreement with small-order key");
                byte[] pm1 = (byte[])Rfc5114P.Clone(); pm1[^1] -= 1;
                T.True(!dhx.CheckPublicKey(pm1), "y = p-1 accepted");
                threw = false;
                try { dhx.Agree(a.PrivateKey, pm1); } catch (WolfCryptFipsException) { threw = true; }
                T.True(threw, "agreement with y = p-1");
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

            T.Run("explicit DH parameters other than (2048, 224/256) are refused", () => {
                /* RFC 2409 group 2: 1024-bit p */
                byte[] p1024 = Convert.FromHexString(
                    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22" +
                    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6" +
                    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                    "FFFFFFFFFFFFFFFF");
                byte[] q160 = new byte[20]; q160[0] = 0x80;
                byte[] p2048 = new byte[256]; p2048[0] = 0x80; p2048[^1] = 1;
                foreach (var (p, q, what) in new[] { (p1024, q160, "1024/160"), (p2048, q160, "2048/160") }) {
                    bool threw = false;
                    try { new FipsDh(p, new byte[] { 2 }, q).Dispose(); } catch (ArgumentException) { threw = true; }
                    T.True(threw, "" + what + " accepted");
                }
            });

            T.Run("explicit FIPS 186-type DH domain (RFC 5114 2.3, 2048/256) generates and agrees", () => {
                using var dhx = new FipsDh(Rfc5114P, Rfc5114G, Rfc5114Q);
                using var a = dhx.GenerateKeyPair(rng);
                using var b = dhx.GenerateKeyPair(rng);
                T.Bytes(dhx.Agree(a.PrivateKey, b.PublicKey), dhx.Agree(b.PrivateKey, a.PublicKey), "Z");
                T.True(dhx.CheckKeyPair(a.PublicKey, a.PrivateKey), "pair check");
            });

            T.Run("explicit DH domains other than the RFC 5114 groups are refused (bad g, composite q)", () => {
                byte[] pm1 = (byte[])Rfc5114P.Clone(); pm1[^1] -= 1;
                BigInteger qv = new BigInteger(Rfc5114Q, isUnsigned: true, isBigEndian: true);
                byte[] qComposite = (qv - qv % 7).ToByteArray(isUnsigned: true, isBigEndian: true);
                var cases = new (byte[] G, byte[] Q, string What)[] {
                    (new byte[] { 1 }, Rfc5114Q, "g = 1"),
                    (pm1, Rfc5114Q, "g = p-1"),
                    (Rfc5114Order7, Rfc5114Q, "g of order 7"),
                    (Rfc5114G, qComposite, "composite q (multiple of 7)"),
                };
                foreach (var (g, q, what) in cases) {
                    bool threw = false;
                    try { new FipsDh(Rfc5114P, g, q).Dispose(); } catch (ArgumentException) { threw = true; }
                    T.True(threw, what + " accepted");
                }
                byte[] padded = new byte[] { 0 }.Concat(Rfc5114P).ToArray();
                new FipsDh(padded, Rfc5114G, Rfc5114Q).Dispose();
            });

            T.Run("explicit DH domain RFC 5114 2.2 (2048/224) generates and agrees", () => {
                using var dhx = new FipsDh(Rfc5114_224P, Rfc5114_224G, Rfc5114_224Q);
                using var a = dhx.GenerateKeyPair(rng);
                using var b = dhx.GenerateKeyPair(rng);
                T.Bytes(dhx.Agree(a.PrivateKey, b.PublicKey), dhx.Agree(b.PrivateKey, a.PublicKey), "Z");
            });

            /* Independent of the module: Z = Y^x mod p and Y = g^x mod p with
             * BigInteger, Z left-padded to len(p) (SP 800-56A 5.7.1.1). Key
             * pairs are regenerated until Z starts with a zero byte, so the
             * wrapper's padding branch runs every time. */
            T.Run("DH Z and public keys match a BigInteger reference, including left-padded Z", () => {
                var domains = new (string Name, FipsDh Dh, byte[] P, byte[] G)[] {
                    ("ffdhe2048", new FipsDh(FipsDhGroup.Ffdhe2048), Ffdhe.P[FipsDhGroup.Ffdhe2048], new byte[] { 2 }),
                    ("RFC 5114 2.3", new FipsDh(Rfc5114P, Rfc5114G, Rfc5114Q), Rfc5114P, Rfc5114G),
                };
                foreach (var (name, dh, p, g) in domains) {
                    using (dh) {
                        using var b = dh.GenerateKeyPair(rng);
                        T.Bytes(ModPow(g, b.PrivateKey, p), b.PublicKey, name + " peer public key");
                        bool padded = false;
                        for (int i = 0; i < 4096 && !padded; i++) {
                            using var a = dh.GenerateKeyPair(rng);
                            byte[] z = dh.Agree(a.PrivateKey, b.PublicKey);
                            T.Bytes(ModPow(b.PublicKey, a.PrivateKey, p), z, name + " Z");
                            padded = z[0] == 0;
                            if (padded)
                                T.Bytes(ModPow(g, a.PrivateKey, p), a.PublicKey, name + " public key");
                        }
                        T.True(padded, name + ": no Z with a leading zero byte in 4096 agreements");
                    }
                }
            });

            /* SP 800-56A FE2OS: public keys are len(p) bytes even when y has
             * a leading zero byte (the module returns the minimal length) */
            T.Run("DH public keys are left-padded to the prime size", () => {
                using var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
                byte[] p = Ffdhe.P[FipsDhGroup.Ffdhe2048];
                bool seen = false;
                for (int i = 0; i < 4096 && !seen; i++) {
                    using var kp = dh.GenerateKeyPair(rng);
                    T.Equal(256, kp.PublicKey.Length, "public key length");
                    if (kp.PublicKey[0] == 0) {
                        seen = true;
                        T.Bytes(ModPow(new byte[] { 2 }, kp.PrivateKey, p), kp.PublicKey, "padded public key");
                        T.True(dh.CheckPublicKey(kp.PublicKey), "padded key validates");
                    }
                }
                T.True(seen, "no public key with a leading zero byte in 4096 key pairs");
            });

            T.Run("only ffdhe2048 is offered (validated KAS-FFC-SSC group)", () => {
                foreach (FipsDhGroup g in new[] { Ffdhe.Ffdhe3072, Ffdhe.Ffdhe4096,
                                                  Ffdhe.Ffdhe6144, Ffdhe.Ffdhe8192 }) {
                    bool threw = false;
                    try { new FipsDh(g).Dispose(); } catch (ArgumentException) { threw = true; }
                    T.True(threw, (int)g + " accepted by the public constructor");
                }
                T.Equal(1, Enum.GetValues<FipsDhGroup>().Length, "public group list");
            });

            T.Run("DH GeneratePublic refuses private keys outside [1, q-1]", () => {
                using var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
                BigInteger qv = (new BigInteger(Ffdhe.P[FipsDhGroup.Ffdhe2048], isUnsigned: true, isBigEndian: true) - 1) / 2;
                foreach (var (x, what) in new[] { (BigInteger.Zero, "0"), (qv, "q"), (qv + 1, "q + 1") }) {
                    byte[] xb = x.IsZero ? new byte[1] : x.ToByteArray(isUnsigned: true, isBigEndian: true);
                    bool threw = false;
                    try { dh.GeneratePublic(xb); } catch (ArgumentException) { threw = true; }
                    catch (NotSupportedException) { threw = false; }
                    T.True(threw, "x = " + what + " accepted");
                }
            });

            T.Run("DH GeneratePublic matches generated key pair (v5.2.3+)", () => {
                using var dh = new FipsDh(FipsDhGroup.Ffdhe2048);
                using var kp = dh.GenerateKeyPair(rng);
                try {
                    byte[] y = dh.GeneratePublic(kp.PrivateKey);
                    T.Bytes(kp.PublicKey, y, "public key");
                    T.Bytes(ModPow(new byte[] { 2 }, kp.PrivateKey, Ffdhe.P[FipsDhGroup.Ffdhe2048]), y, "2^x mod p");
                }
                catch (NotSupportedException e) { T.Skip(e.Message); }
            });
        }

        /* RFC 5114 section 2.3: 2048-bit MODP group, 256-bit prime order subgroup */
        private static readonly byte[] Rfc5114P = T.Hex("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4" +
                "FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED" +
                "91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C" +
                "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E" +
                "F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856" +
                "DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F" +
                "693877FAD7EF09CADB094AE91E1A1597");
        private static readonly byte[] Rfc5114G = T.Hex("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463F" +
                "FF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A65" +
                "0196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83" +
                "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A" +
                "DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC37" +
                "7FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D4795451" +
                "5E2327CFEF98C582664B4C0F6CC41659");
        private static readonly byte[] Rfc5114Q = T.Hex("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3");
        /* RFC 5114 section 2.2: 2048-bit MODP group, 224-bit prime order subgroup */
        private static readonly byte[] Rfc5114_224P = T.Hex("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DB" +
                "AF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8" +
                "D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708" +
                "B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074" +
                "15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9" +
                "C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71" +
                "CF9DE5384E71B81C0AC4DFFE0C10E64F");
        private static readonly byte[] Rfc5114_224G = T.Hex("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0" +
                "DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024A" +
                "F4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE" +
                "F180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC" +
                "B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD" +
                "566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179" +
                "81BC087F2A7065B384B890D3191F2BFA");
        private static readonly byte[] Rfc5114_224Q = T.Hex("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB");

        /* element of order 7 in the RFC 5114 2.3 group */
        private static readonly byte[] Rfc5114Order7 = T.Hex("7E22FAD9CC23B5949616A26B060DCEC3557A81D98DC45F51943F4E29B06DD73E6FBF201C01C4C262" +
                "0B81698048FCB21655D1276BFB402A41C3AF50528F2DF02B3440A3B7A1855DFE31A549DDCE9563ED" +
                "18FE1530A3A649F87FA4D427D6D2E1B73CF3848177651080F2CA96628FED411C331D9E28D28DA5F0" +
                "C65F2516F9BB4C72E4C9050F5D654BCC0139E66FBC582AE32D345AD84A249D9CEA131C6A9AF59ECA" +
                "EFBC190CA265394EB8190FF91A6AF58327060CA4900829EAA3A1C26F86737D7510BFD55C430BCC1F" +
                "2DB6A62C3BFE1717E5236945C475BB7B36DC2FA5AB06B089325DFD864A6B044622E62A5638CE23F3" +
                "19CF564826CE1E5C1BC1166896C5F205");

        /* base^exp mod m, big-endian, left-padded to len(m) */
        private static byte[] ModPow(byte[] b, byte[] e, byte[] m)
        {
            int len = m.SkipWhile(x => x == 0).Count();
            byte[] r = BigInteger.ModPow(new BigInteger(b, isUnsigned: true, isBigEndian: true),
                                         new BigInteger(e, isUnsigned: true, isBigEndian: true),
                                         new BigInteger(m, isUnsigned: true, isBigEndian: true))
                                 .ToByteArray(isUnsigned: true, isBigEndian: true);
            return new byte[len - r.Length].Concat(r).ToArray();
        }

        private static string Mode(AcvpVectorSet s) => s.Request.GetProperty("mode").GetString()!;

        private static FipsEccCurve CurveOf(string c) => c switch {
            "P-192" => FipsEccCurve.P192, "P-224" => FipsEccCurve.P224, "P-256" => FipsEccCurve.P256,
            "P-384" => FipsEccCurve.P384, "P-521" => FipsEccCurve.P521,
            _ => throw new Exception("curve " + c)
        };

        private static FipsDhGroup GroupOf(string g) => g switch {
            "ffdhe2048" => FipsDhGroup.Ffdhe2048, "ffdhe3072" => Ffdhe.Ffdhe3072,
            "ffdhe4096" => Ffdhe.Ffdhe4096, "ffdhe6144" => Ffdhe.Ffdhe6144,
            "ffdhe8192" => Ffdhe.Ffdhe8192, _ => throw new Exception("group " + g)
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
