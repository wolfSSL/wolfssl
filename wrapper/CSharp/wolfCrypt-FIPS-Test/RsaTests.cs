/* RsaTests.cs
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
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

namespace wolfSSL.CSharp.Fips.Test
{
    /* RSA tests. The v5.2.3 boundary has no RSA key import, so ACVP vectors
     * that supply a key (keyGen, sigVer, decryptionPrimitive) cannot be run
     * through the module. Instead, module output is checked independently
     * with .NET's RSA implementation (test code only). */
    internal static class RsaTests
    {
        private static FipsRsaKey? key2048;

        public static void Run()
        {
            T.Section("RSA");
            using var rng = new FipsRng();

            T.Run("generate 2048 and 3072-bit keys, key check passes", () => {
                key2048 = FipsRsaKey.Generate(2048, rng);
                T.Equal(256, key2048.Size, "2048 size");
                key2048.Check();
                using var k3 = FipsRsaKey.Generate(3072, rng);
                T.Equal(384, k3.Size, "3072 size");
                k3.Check();
            });
            FipsRsaKey key = key2048 ?? FipsRsaKey.Generate(2048, rng);

            T.Run("export is locked by default (FIPS_PRIVATE_KEY_LOCKED_E)", () => {
                FipsModule.SetPrivateKeyReadEnable(false);
                T.Throws(FipsError.FIPS_PRIVATE_KEY_LOCKED_E, () => key.Export(), "locked export");
            });

            T.Run("private key read gate is per thread", () => {
                FipsModule.SetPrivateKeyReadEnable(false);
                var other = new Thread(() => FipsModule.SetPrivateKeyReadEnable(true));
                other.Start();
                other.Join();
                T.Throws(FipsError.FIPS_PRIVATE_KEY_LOCKED_E, () => key.Export(), "unlocked by another thread");
            });

            RSA net = WithUnlocked(() => {
                using FipsRsaKeyComponents exported = key.Export();   /* zeroes D, P, Q, ... */
                return ToDotNet(exported);
            });
            RSA netPub = WithUnlocked(() => {
                var pub = key.ExportPublic();
                return RSA.Create(new RSAParameters { Modulus = pub.Modulus, Exponent = pub.Exponent });
            });

            T.Run("ExportPublic works without unlocking the gate and leaves it locked", () => {
                FipsModule.SetPrivateKeyReadEnable(false);
                var pub = key.ExportPublic();
                T.Equal(256, pub.Modulus.Length, "modulus");
                T.True(!FipsModule.PrivateKeyReadEnabled, "gate left enabled");
                T.Throws(FipsError.FIPS_PRIVATE_KEY_LOCKED_E, () => key.Export(), "full export still locked");
            });

            T.Run("exported key is consistent (n = p*q)", () => {
                using var c = WithUnlocked(() => key.Export());
                T.True(U(c.N) == U(c.P) * U(c.Q), "n != p*q");
            });

            foreach (var (fh, nh) in new[] { (FipsHashType.Sha224, HashAlgorithmName.SHA256),
                                             (FipsHashType.Sha256, HashAlgorithmName.SHA256),
                                             (FipsHashType.Sha384, HashAlgorithmName.SHA384),
                                             (FipsHashType.Sha512, HashAlgorithmName.SHA512) }) {
                if (fh == FipsHashType.Sha224) {
                    T.Run("PKCS#1 v1.5 SHA-224 sign/verify (module)", () => {
                        byte[] d = FipsHash.Compute(fh, new byte[] { 1, 2, 3 });
                        T.True(Pkcs1.Verify(key, fh, d, Pkcs1.Sign(key, fh, d, rng)), "verify");
                    });
                    continue;
                }
                T.Run("PKCS#1 v1.5 " + fh + ": module signature verifies in .NET", () => {
                    byte[] msg = System.Text.Encoding.ASCII.GetBytes("wolfCrypt FIPS " + fh);
                    byte[] d = FipsHash.Compute(fh, msg);
                    byte[] sig = Pkcs1.Sign(key, fh, d, rng);
                    T.True(Pkcs1.Verify(key, fh, d, sig), "module verify");
                    T.True(netPub.VerifyHash(d, sig, nh, RSASignaturePadding.Pkcs1), ".NET verify");
                });
                T.Run("PSS " + fh + ": module signature verifies in .NET", () => {
                    byte[] d = FipsHash.Compute(fh, new byte[] { 7, 7, 7 });
                    byte[] sig = key.SignPss(fh, d, rng);
                    T.True(key.VerifyPss(fh, d, sig), "module verify");
                    T.True(netPub.VerifyHash(d, sig, nh, RSASignaturePadding.Pss), ".NET verify");
                });
            }

            /* RSA SigGen is validated for SHA-2 only; SHA-3 PKCS#1 v1.5
             * signatures can still be verified (see the DigestInfo test) */
            T.Run("PKCS#1 v1.5 signing with SHA-3 is refused", () => {
                foreach (FipsHashType h in new[] { FipsHashType.Sha3_224, FipsHashType.Sha3_256,
                                                   FipsHashType.Sha3_384, FipsHashType.Sha3_512 }) {
                    bool threw = false;
                    try { Pkcs1.Sign(key, h, FipsHash.Compute(h, new byte[] { 4 }), rng); } catch (ArgumentException) { threw = true; }
                    T.True(threw, h + " signed");
                }
            });

            /* The wrapper builds DigestInfo from its own DER prefixes. Decode
             * each signature independently (s^e mod n, RFC 8017 9.2 padding,
             * AsnReader) and compare the OID with its dotted form, so a wrong
             * prefix byte fails even for hashes .NET cannot verify here. */
            T.Run("PKCS#1 v1.5 DigestInfo decodes to the right OID for every hash", () => {
                var pub = key.ExportPublic();
                BigInteger n = U(pub.Modulus), e = U(pub.Exponent);
                var oids = new (FipsHashType, string)[] {
                    (FipsHashType.Sha224, "2.16.840.1.101.3.4.2.4"), (FipsHashType.Sha256, "2.16.840.1.101.3.4.2.1"),
                    (FipsHashType.Sha384, "2.16.840.1.101.3.4.2.2"), (FipsHashType.Sha512, "2.16.840.1.101.3.4.2.3"),
                    (FipsHashType.Sha3_224, "2.16.840.1.101.3.4.2.7"), (FipsHashType.Sha3_256, "2.16.840.1.101.3.4.2.8"),
                    (FipsHashType.Sha3_384, "2.16.840.1.101.3.4.2.9"), (FipsHashType.Sha3_512, "2.16.840.1.101.3.4.2.10"),
                };
                using var comps = WithUnlocked(() => key.Export());
                BigInteger dPriv = U(comps.D);
                foreach (var (h, oid) in oids) {
                    byte[] d = FipsHash.Compute(h, new byte[] { 7, 7, (byte)h });
                    if (h >= FipsHashType.Sha3_224) {
                        /* SHA-3: signing is refused, so build the signature
                         * here (independent DigestInfo, s = EM^d mod n) and
                         * check the module verifies it with the wrapper's
                         * prefix */
                        var w = new AsnWriter(AsnEncodingRules.DER);
                        using (w.PushSequence()) {
                            using (w.PushSequence()) {
                                w.WriteObjectIdentifier(oid);
                                w.WriteNull();
                            }
                            w.WriteOctetString(d);
                        }
                        byte[] di = w.Encode();
                        byte[] emOwn = new byte[key.Size];
                        emOwn[1] = 1;
                        for (int i = 2; i < key.Size - di.Length - 1; i++) emOwn[i] = 0xFF;
                        di.CopyTo(emOwn, key.Size - di.Length);
                        byte[] s3 = BigInteger.ModPow(U(emOwn), dPriv, n).ToByteArray(isUnsigned: true, isBigEndian: true);
                        s3 = new byte[key.Size - s3.Length].Concat(s3).ToArray();
                        T.True(Pkcs1.Verify(key, h, d, s3), h + " module verifies an independent signature");
                        continue;
                    }
                    byte[] sig = Pkcs1.Sign(key, h, d, rng);
                    byte[] em = BigInteger.ModPow(U(sig), e, n).ToByteArray(isUnsigned: true, isBigEndian: true);
                    em = new byte[key.Size - em.Length].Concat(em).ToArray();
                    int sep = Array.IndexOf(em, (byte)0, 2);
                    T.True(em[0] == 0 && em[1] == 1 && sep >= 10 && em.Skip(2).Take(sep - 2).All(b => b == 0xFF),
                           h + " EMSA-PKCS1-v1_5 padding");
                    var outer = new AsnReader(em.AsMemory(sep + 1), AsnEncodingRules.DER);
                    AsnReader info = outer.ReadSequence();
                    AsnReader alg = info.ReadSequence();
                    T.Equal(oid, alg.ReadObjectIdentifier(), h + " OID");
                    alg.ReadNull();
                    T.True(!alg.HasData, h + " algorithm parameters");
                    T.Bytes(d, info.ReadOctetString(), h + " digest");
                    T.True(!info.HasData && !outer.HasData, h + " trailing data");
                    T.True(Pkcs1.Verify(key, h, d, sig), h + " module verify");
                }
            });

            /* the module signs any block; the wrapper accepts only the exact
             * DER DigestInfo of a SHA-2 digest */
            T.Run("SignPkcs1v15 refuses anything but a SHA-2 DigestInfo", () => {
                byte[] d256 = FipsHash.Compute(FipsHashType.Sha256, new byte[] { 3 });
                byte[] good = Pkcs1.DigestInfo(FipsHashType.Sha256, d256);
                byte[] noNull = new byte[] { 0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                                             0x04, 0x20 }.Concat(d256).ToArray();   /* parameters omitted */
                var bad = new (byte[] Di, string What)[] {
                    (d256, "raw digest"),
                    (new byte[0], "empty"),
                    (good.Concat(new byte[] { 0 }).ToArray(), "trailing byte"),
                    (good.Take(good.Length - 1).ToArray(), "short digest"),
                    (noNull, "non-canonical (no NULL parameters)"),
                    (Pkcs1.DigestInfo(FipsHashType.Sha256, new byte[31]), "31-byte SHA-256 digest"),
                    (Pkcs1.DigestInfo(FipsHashType.Sha1, new byte[20]), "SHA-1"),
                    (Pkcs1.DigestInfo(FipsHashType.Sha3_256, new byte[32]), "SHA3-256"),
                    (Enumerable.Repeat((byte)0x41, 51).ToArray(), "arbitrary 51 bytes"),
                };
                foreach (var (di, what) in bad) {
                    bool threw = false;
                    try { key.SignPkcs1v15(di, rng); } catch (ArgumentException) { threw = true; }
                    T.True(threw, what + " signed");
                }
                byte[] sig = key.SignPkcs1v15(good, rng);
                T.Bytes(good, key.RecoverPkcs1v15(sig)!, "recovered block is the DigestInfo");
                sig[0] ^= 1;
                T.True(key.RecoverPkcs1v15(sig) == null || !key.RecoverPkcs1v15(sig)!.SequenceEqual(good), "tampered signature recovers the DigestInfo");
            });

            T.Run("tampered signature or digest does not verify", () => {
                byte[] d = FipsHash.Compute(FipsHashType.Sha256, new byte[] { 1 });
                byte[] sig = Pkcs1.Sign(key, FipsHashType.Sha256, d, rng);
                byte[] pss = key.SignPss(FipsHashType.Sha256, d, rng);
                byte[] d2 = (byte[])d.Clone(); d2[0] ^= 1;
                T.True(!Pkcs1.Verify(key, FipsHashType.Sha256, d2, sig), "v1.5 wrong digest");
                T.True(!key.VerifyPss(FipsHashType.Sha256, d2, pss), "PSS wrong digest");
                sig[10] ^= 1; pss[10] ^= 1;
                T.True(!Pkcs1.Verify(key, FipsHashType.Sha256, d, sig), "v1.5 tampered sig");
                T.True(!key.VerifyPss(FipsHashType.Sha256, d, pss), "PSS tampered sig");
            });

            T.Run("ACVP RSA sigGen messages: module signatures verify in .NET", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("RSA")) {
                    if (set.Request.GetProperty("mode").GetString() != "sigGen")
                        continue;
                    foreach (var g in set.Groups) {
                        string? h = g.GetProperty("hashAlg").GetString();
                        string sigType = g.GetProperty("sigType").GetString()!;
                        if (g.GetProperty("modulo").GetInt32() != 2048 || !h!.StartsWith("SHA2-") ||
                            h.StartsWith("SHA2-512/") || h == "SHA2-224" ||
                            (sigType != "pkcs1v1.5" && sigType != "pss"))
                            continue;
                        FipsHashType ft = h switch { "SHA2-256" => FipsHashType.Sha256,
                            "SHA2-384" => FipsHashType.Sha384, _ => FipsHashType.Sha512 };
                        HashAlgorithmName nh = h switch { "SHA2-256" => HashAlgorithmName.SHA256,
                            "SHA2-384" => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            byte[] d = FipsHash.Compute(ft, Acvp.Hex(t, "message"));
                            bool ok = sigType == "pss"
                                ? netPub.VerifyHash(d, key.SignPss(ft, d, rng), nh, RSASignaturePadding.Pss)
                                : netPub.VerifyHash(d, Pkcs1.Sign(key, ft, d, rng), nh, RSASignaturePadding.Pkcs1);
                            T.True(ok, set.File + " tcId " + t.GetProperty("tcId").GetInt32());
                            n++;
                        }
                    }
                }
                T.True(n > 0, "no applicable sigGen groups");
                Console.WriteLine("        " + n + " sigGen messages (2048-bit, SHA2-256/384/512)");
            });

            T.Run("ACVP RSA sigVer / keyGen / decryptionPrimitive", () =>
                T.Skip("need RSA key import; the v5.2.3 boundary has none (key decode is in asn.c)"));

            T.Run("OAEP SHA-256: .NET encrypts to module public key, module decrypts", () => {
                byte[] pt = { 1, 2, 3, 4, 5, 6, 7, 8 };
                byte[] ct = netPub.Encrypt(pt, RSAEncryptionPadding.OaepSHA256);
                T.Bytes(pt, key.Decrypt(ct), "decrypt");
            });

            T.Run("OAEP SHA-256: module encrypts, .NET decrypts", () => {
                byte[] pt = { 9, 8, 7 };
                T.Bytes(pt, net.Decrypt(key.Encrypt(pt, rng), RSAEncryptionPadding.OaepSHA256), ".NET decrypt");
            });

            T.Run("OAEP with label and with SHA-384 round trip", () => {
                byte[] pt = { 42 }, label = { 1, 1 };
                T.Bytes(pt, key.Decrypt(key.Encrypt(pt, rng, FipsHashType.Sha256, label), FipsHashType.Sha256, label), "label");
                T.Bytes(pt, key.Decrypt(key.Encrypt(pt, rng, FipsHashType.Sha384), FipsHashType.Sha384), "SHA-384");
            });

            T.Run("OAEP decrypt with wrong label fails with the padding error", () => {
                byte[] ct = key.Encrypt(new byte[] { 1 }, rng, FipsHashType.Sha256, new byte[] { 1 });
                T.Bytes(new byte[] { 1 }, key.Decrypt(ct, FipsHashType.Sha256, new byte[] { 1 }), "right label decrypts");
                T.Throws(FipsError.RSA_BUFFER_E, () => key.Decrypt(ct, FipsHashType.Sha256, new byte[] { 2 }), "wrong label");
            });

            /* FIPS builds #undef WC_RSA_BLINDING (settings.h), so RsaKey has
             * no rng member and private operations need no DRBG; the module
             * never keeps the generation DRBG. No FipsRng is allocated after
             * the generation DRBG is freed (.NET encrypts), so a dangling
             * pointer could not land on a live DRBG, and the heap is churned
             * between operations. */
            T.Run("OAEP decrypt needs no DRBG after the generation DRBG is freed", () => {
                FipsRsaKey k2;
                using (var genRng = new FipsRng())
                    k2 = FipsRsaKey.Generate(2048, genRng);
                using (k2) {
                    var pub = k2.ExportPublic();
                    using var enc = RSA.Create(new RSAParameters { Modulus = pub.Modulus, Exponent = pub.Exponent });
                    var churn = new List<byte[]>();
                    for (int i = 0; i < 20; i++) {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                        byte[] m = { (byte)i, 5, 6 };
                        T.Bytes(m, k2.Decrypt(enc.Encrypt(m, RSAEncryptionPadding.OaepSHA256)), "decrypt " + i);
                        churn.Add(new byte[4096 * (i + 1)]);
                        IntPtr p = Marshal.AllocHGlobal(1024);   /* reuse native blocks */
                        Marshal.FreeHGlobal(p);
                    }
                }
            });

            T.Run("approved key size list cannot be modified", () => {
                bool threw = false;
                try { ((System.Collections.Generic.IList<int>)FipsRsaKey.ApprovedKeySizes)[0] = 1024; }
                catch (NotSupportedException) { threw = true; }
                T.True(threw, "list modified");
                T.True(FipsRsaKey.ApprovedKeySizes.SequenceEqual(new[] { 2048, 3072, 4096 }), "sizes");
            });

            T.Run("PKCS#1 v1.5 encryption is not offered (OAEP only)", () => {
                T.True(typeof(FipsRsaKey).Assembly.GetType("wolfSSL.CSharp.Fips.FipsRsaPadding") == null,
                       "FipsRsaPadding still present");
            });

            T.Run("SHA-1 signature generation is refused (PKCS#1 v1.5 and PSS)", () => {
                byte[] d = new byte[20];
                bool threw = false;
                try { Pkcs1.Sign(key, FipsHashType.Sha1, d, rng); } catch (ArgumentException) { threw = true; }
                T.True(threw, "SHA-1 PKCS#1 v1.5 signed");
                threw = false;
                try { key.SignPss(FipsHashType.Sha1, d, rng); } catch (ArgumentException) { threw = true; }
                T.True(threw, "SHA-1 PSS signed");
            });

            /* WOLFSSL_PSS_LONG_SALT builds drop the module's sLen <= hLen
             * check, so the wrapper enforces FIPS 186-5 5.4(g) */
            T.Run("PSS salt length limited to the digest length (FIPS 186-5 5.4(g))", () => {
                foreach (FipsHashType h in new[] { FipsHashType.Sha256, FipsHashType.Sha384, FipsHashType.Sha512 }) {
                    int hLen = FipsHash.DigestSizeOf(h);
                    byte[] d = FipsHash.Compute(h, new byte[] { 9 });
                    foreach (int s in new[] { 0, hLen }) {
                        byte[] sig = key.SignPss(h, d, rng, s);
                        T.True(key.VerifyPss(h, d, sig, s), h + " salt " + s);
                    }
                    foreach (int s in new[] { hLen + 1, 222, -2, -3 }) {
                        bool signThrew = false, verifyThrew = false;
                        try { key.SignPss(h, d, rng, s); } catch (ArgumentOutOfRangeException) { signThrew = true; }
                        try { key.VerifyPss(h, d, new byte[key.Size], s); } catch (ArgumentOutOfRangeException) { verifyThrew = true; }
                        T.True(signThrew && verifyThrew, h + " salt " + s + " accepted");
                    }
                }
            });

            T.Run("public exponent must be odd and above 2^16 (FIPS 186-5 5.4(e))", () => {
                foreach (long e in new long[] { 3, 17, 65536, 65538 }) {
                    bool threw = false;
                    try { FipsRsaKey.Generate(2048, rng, e).Dispose(); } catch (ArgumentOutOfRangeException) { threw = true; }
                    T.True(threw, "e = " + e + " accepted");
                }
                using var ok = FipsRsaKey.Generate(2048, rng, 65539);
                ok.Check();
            });

            /* The module itself accepts 1024 (bug 6367); the wrapper must not. */
            T.Run("non-approved key sizes are refused (1024, 1536, 2047)", () => {
                foreach (int bits in new[] { 1024, 1536, 2047 }) {
                    bool threw = false;
                    try { FipsRsaKey.Generate(bits, rng).Dispose(); } catch (ArgumentException) { threw = true; }
                    T.True(threw, bits + "-bit key generated");
                }
            });

            key.Dispose();
            net.Dispose();
            netPub.Dispose();
        }

        private static TR WithUnlocked<TR>(Func<TR> f)
        {
            FipsModule.SetPrivateKeyReadEnable(true);
            try { return f(); }
            finally { FipsModule.SetPrivateKeyReadEnable(false); }
        }

        private static BigInteger U(byte[] b) => new BigInteger(b, isUnsigned: true, isBigEndian: true);

        private static byte[] B(BigInteger v, int len)
        {
            byte[] b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
            return b.Length == len ? b : new byte[len - b.Length].Concat(b).ToArray();
        }

        private static RSA ToDotNet(FipsRsaKeyComponents c)
        {
            BigInteger p = U(c.P), q = U(c.Q), d = U(c.D);
            int half = c.P.Length;
            var prm = new RSAParameters {
                Modulus = c.N, Exponent = c.E, D = B(d, c.N.Length), P = c.P, Q = c.Q,
                DP = B(d % (p - 1), half), DQ = B(d % (q - 1), half),
                InverseQ = B(BigInteger.ModPow(q, p - 2, p), half)
            };
            return RSA.Create(prm);
        }
    }
}
