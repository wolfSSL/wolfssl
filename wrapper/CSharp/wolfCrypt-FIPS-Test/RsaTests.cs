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
using System.Linq;
using System.Numerics;
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

            RSA net = WithUnlocked(() => ToDotNet(key.Export()));
            RSA netPub = WithUnlocked(() => {
                var pub = key.ExportPublic();
                return RSA.Create(new RSAParameters { Modulus = pub.Modulus, Exponent = pub.Exponent });
            });

            T.Run("exported key is consistent (n = p*q)", () => {
                var c = WithUnlocked(() => key.Export());
                T.True(U(c.N) == U(c.P) * U(c.Q), "n != p*q");
            });

            foreach (var (fh, nh) in new[] { (FipsHashType.Sha224, HashAlgorithmName.SHA256),
                                             (FipsHashType.Sha256, HashAlgorithmName.SHA256),
                                             (FipsHashType.Sha384, HashAlgorithmName.SHA384),
                                             (FipsHashType.Sha512, HashAlgorithmName.SHA512) }) {
                if (fh == FipsHashType.Sha224) {
                    T.Run("PKCS#1 v1.5 SHA-224 sign/verify (module)", () => {
                        byte[] d = FipsHash.Compute(fh, new byte[] { 1, 2, 3 });
                        T.True(key.VerifyPkcs1v15(fh, d, key.SignPkcs1v15(fh, d, rng)), "verify");
                    });
                    continue;
                }
                T.Run("PKCS#1 v1.5 " + fh + ": module signature verifies in .NET", () => {
                    byte[] msg = System.Text.Encoding.ASCII.GetBytes("wolfCrypt FIPS " + fh);
                    byte[] d = FipsHash.Compute(fh, msg);
                    byte[] sig = key.SignPkcs1v15(fh, d, rng);
                    T.True(key.VerifyPkcs1v15(fh, d, sig), "module verify");
                    T.True(netPub.VerifyHash(d, sig, nh, RSASignaturePadding.Pkcs1), ".NET verify");
                });
                T.Run("PSS " + fh + ": module signature verifies in .NET", () => {
                    byte[] d = FipsHash.Compute(fh, new byte[] { 7, 7, 7 });
                    byte[] sig = key.SignPss(fh, d, rng);
                    T.True(key.VerifyPss(fh, d, sig), "module verify");
                    T.True(netPub.VerifyHash(d, sig, nh, RSASignaturePadding.Pss), ".NET verify");
                });
            }

            T.Run("PKCS#1 v1.5 SHA3-256 sign/verify (module)", () => {
                byte[] d = FipsHash.Compute(FipsHashType.Sha3_256, new byte[] { 4, 5, 6 });
                T.True(key.VerifyPkcs1v15(FipsHashType.Sha3_256, d,
                    key.SignPkcs1v15(FipsHashType.Sha3_256, d, rng)), "verify");
            });

            T.Run("tampered signature or digest does not verify", () => {
                byte[] d = FipsHash.Compute(FipsHashType.Sha256, new byte[] { 1 });
                byte[] sig = key.SignPkcs1v15(FipsHashType.Sha256, d, rng);
                byte[] pss = key.SignPss(FipsHashType.Sha256, d, rng);
                byte[] d2 = (byte[])d.Clone(); d2[0] ^= 1;
                T.True(!key.VerifyPkcs1v15(FipsHashType.Sha256, d2, sig), "v1.5 wrong digest");
                T.True(!key.VerifyPss(FipsHashType.Sha256, d2, pss), "PSS wrong digest");
                sig[10] ^= 1; pss[10] ^= 1;
                T.True(!key.VerifyPkcs1v15(FipsHashType.Sha256, d, sig), "v1.5 tampered sig");
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
                                : netPub.VerifyHash(d, key.SignPkcs1v15(ft, d, rng), nh, RSASignaturePadding.Pkcs1);
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

            T.Run("OAEP with label, and PKCS#1 v1.5 encryption round trip", () => {
                byte[] pt = { 42 }, label = { 1, 1 };
                T.Bytes(pt, key.Decrypt(key.Encrypt(pt, rng, FipsRsaPadding.Oaep, FipsHashType.Sha256, label),
                    FipsRsaPadding.Oaep, FipsHashType.Sha256, label), "OAEP label");
                T.Bytes(pt, key.Decrypt(key.Encrypt(pt, rng, FipsRsaPadding.Pkcs1v15), FipsRsaPadding.Pkcs1v15), "v1.5");
            });

            T.Run("OAEP decrypt with wrong label fails", () => {
                byte[] ct = key.Encrypt(new byte[] { 1 }, rng, FipsRsaPadding.Oaep, FipsHashType.Sha256, new byte[] { 1 });
                bool threw = false;
                try { key.Decrypt(ct, FipsRsaPadding.Oaep, FipsHashType.Sha256, new byte[] { 2 }); }
                catch (WolfCryptFipsException) { threw = true; }
                T.True(threw, "wrong label accepted");
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
