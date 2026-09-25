/* KnownAnswerTests.cs
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
using System.Text;

namespace wolfSSL.CSharp.Fips.Test
{
    /* Embedded known answers that run without the ACVP vectors
     * (WOLFACVP_VECTORS). The module CASTs test the module; these test the
     * wrapper's marshalling, entry point and parameter mapping for each
     * symmetric service: published vectors (FIPS 180-4 / 202 "abc",
     * RFC 4231, SP 800-38A F.1-F.5, RFC 4493, GCM test case 2, RFC 3610,
     * CAVS Hash_DRBG) plus .NET cross-checks where .NET has the primitive. */
    internal static class KnownAnswerTests
    {
        /* SP 800-38A F.1-F.5: AES-128 key and the first two plaintext blocks */
        private static readonly byte[] Key38A = T.Hex("2b7e151628aed2a6abf7158809cf4f3c");
        private static readonly byte[] Pt38A = T.Hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        private static readonly byte[] Iv38A = T.Hex("000102030405060708090a0b0c0d0e0f");

        public static void Run()
        {
            T.Section("Embedded known answers (no ACVP vectors needed)");

            T.Run("SHA-1/2/3 of \"abc\" (FIPS 180-4, FIPS 202)", () =>
            {
                byte[] abc = Encoding.ASCII.GetBytes("abc");
                var expected = new (FipsHashType, string)[] {
                    (FipsHashType.Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
                    (FipsHashType.Sha224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
                    (FipsHashType.Sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                    (FipsHashType.Sha384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" +
                                          "8086072ba1e7cc2358baeca134c825a7"),
                    (FipsHashType.Sha512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                                          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
                    (FipsHashType.Sha3_224, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
                    (FipsHashType.Sha3_256, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
                    (FipsHashType.Sha3_384, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2" +
                                            "98d88cea927ac7f539f1edf228376d25"),
                    (FipsHashType.Sha3_512, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" +
                                            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
                };
                foreach (var (type, hex) in expected)
                {
                    T.Bytes(T.Hex(hex), FipsHash.Compute(type, abc), type.ToString());
                }
            });

            T.Run("HMAC (RFC 4231 test case 1) and .NET cross-check", () =>
            {
                byte[] key = Enumerable.Repeat((byte)0x0b, 20).ToArray();
                byte[] msg = Encoding.ASCII.GetBytes("Hi There");
                var expected = new (FipsHashType, string)[] {
                    (FipsHashType.Sha1, "b617318655057264e28bc0b6fb378c8ef146be00"),
                    (FipsHashType.Sha224, "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"),
                    (FipsHashType.Sha256, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                    (FipsHashType.Sha384, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c" +
                                          "faea9ea9076ede7f4af152e8b2fa9cb6"),
                    (FipsHashType.Sha512, "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
                                          "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
                    (FipsHashType.Sha3_256, "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"),
                };
                foreach (var (type, hex) in expected)
                {
                    T.Bytes(T.Hex(hex), FipsHmac.Compute(type, key, msg), "HMAC-" + type);
                }

                byte[] k32 = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
                byte[] data = Enumerable.Range(0, 300).Select(i => (byte)(i * 7)).ToArray();
                T.Bytes(HMACSHA256.HashData(k32, data), FipsHmac.Compute(FipsHashType.Sha256, k32, data), ".NET HMAC-SHA-256");
                T.Bytes(HMACSHA512.HashData(k32, data), FipsHmac.Compute(FipsHashType.Sha512, k32, data), ".NET HMAC-SHA-512");
            });

            T.Run("AES-128 ECB/CBC/OFB/CTR (SP 800-38A F.1-F.5), both directions", () =>
            {
                var cases = new (string Mode, byte[] Ct, Func<bool, FipsAes> Make)[] {
                    ("ECB", T.Hex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"),
                        enc => FipsAes.CreateEcb(Key38A, enc)),
                    ("CBC", T.Hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"),
                        enc => FipsAes.CreateCbc(Key38A, Iv38A, enc)),
                    ("OFB", T.Hex("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"),
                        enc => FipsAes.CreateOfb(Key38A, Iv38A, enc)),
                    ("CTR", T.Hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"),
                        _ => FipsAes.CreateCtr(Key38A, T.Hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))),
                };
                foreach (var (mode, ct, make) in cases)
                {
                    using (var e = make(true))
                    {
                        T.Bytes(ct, e.Transform(Pt38A), mode + " encrypt");
                    }

                    using (var d = make(false))
                    {
                        T.Bytes(Pt38A, d.Transform(ct), mode + " decrypt");
                    }
                }
                /* .NET cross-check with an independent key, IV and length */
                byte[] key = Enumerable.Range(0, 32).Select(i => (byte)(i * 3 + 1)).ToArray();
                byte[] iv = Enumerable.Range(0, 16).Select(i => (byte)(255 - i)).ToArray();
                byte[] pt = Enumerable.Range(0, 96).Select(i => (byte)(i * 11)).ToArray();
                using var net = Aes.Create();
                net.Key = key;
                using var cbc = FipsAes.CreateCbc(key, iv, true);
                T.Bytes(net.EncryptCbc(pt, iv, PaddingMode.None), cbc.Transform(pt), ".NET AES-256-CBC");
                using var ecb = FipsAes.CreateEcb(key, true);
                T.Bytes(net.EncryptEcb(pt, PaddingMode.None), ecb.Transform(pt), ".NET AES-256-ECB");
            });

            T.Run("CMAC-AES-128 (RFC 4493 example 2)", () =>
            {
                T.Bytes(T.Hex("070a16b46b4d4144f79bdd9dd04a287c"),
                        FipsCmac.Compute(Key38A, Pt38A.Take(16).ToArray()), "tag");
            });

            T.Run("AES-GCM (test case 2, external IV) and .NET cross-check", () =>
            {
                using var gcm = new FipsAesGcm(new byte[16]);
                var r = gcm.EncryptWithIV(new byte[12], new byte[16]);
                T.Bytes(T.Hex("0388dace60b6a392f328c2b971b2fe78"), r.Ciphertext, "ciphertext");
                T.Bytes(T.Hex("ab6e47d42cec13bdf53a67b21257bddf"), r.Tag, "tag");
                T.Bytes(new byte[16], gcm.Decrypt(r.IV, r.Ciphertext, r.Tag), "decrypt");
                if (!AesGcm.IsSupported)
                {
                    Console.WriteLine("        .NET AesGcm not supported on this platform; cross-check skipped");
                    return;
                }
                byte[] key = Enumerable.Range(0, 32).Select(i => (byte)(i + 5)).ToArray();
                byte[] iv = Enumerable.Range(0, 12).Select(i => (byte)(i * 9)).ToArray();
                byte[] pt = Enumerable.Range(0, 45).Select(i => (byte)(i ^ 0x5a)).ToArray();
                byte[] aad = { 1, 2, 3, 4, 5 };
                byte[] nct = new byte[pt.Length], ntag = new byte[16];
                using (var n = new AesGcm(key, 16))
                {
                    n.Encrypt(iv, pt, nct, ntag, aad);
                }

                using var g2 = new FipsAesGcm(key);
                var r2 = g2.EncryptWithIV(iv, pt, aad);
                T.Bytes(nct, r2.Ciphertext, ".NET ciphertext");
                T.Bytes(ntag, r2.Tag, ".NET tag");
                T.Bytes(pt, g2.Decrypt(iv, nct, ntag, aad), "decrypt .NET output");
            });

            T.Run("AES-CCM (RFC 3610 packet vector 1) and .NET cross-check", () =>
            {
                byte[] key = T.Hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
                byte[] nonce = T.Hex("00000003020100a0a1a2a3a4a5");
                byte[] aad = T.Hex("0001020304050607");
                byte[] pt = T.Hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
                using var ccm = new FipsAesCcm(key);
                ccm.SetNonce(nonce);
                var r = ccm.Encrypt(pt, aad, 8);
                T.Bytes(T.Hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"), r.Ciphertext, "ciphertext");
                T.Bytes(T.Hex("17e8d12cfdf926e0"), r.Tag, "tag");
                T.Bytes(pt, ccm.Decrypt(nonce, r.Ciphertext, r.Tag, aad, 8), "decrypt");
                if (!AesCcm.IsSupported)
                {
                    Console.WriteLine("        .NET AesCcm not supported on this platform; cross-check skipped");
                    return;
                }
                byte[] k2 = Enumerable.Range(0, 16).Select(i => (byte)(i * 13)).ToArray();
                byte[] n2 = Enumerable.Range(0, 12).Select(i => (byte)(i + 100)).ToArray();
                byte[] p2 = Enumerable.Range(0, 40).Select(i => (byte)i).ToArray();
                byte[] nct = new byte[p2.Length], ntag = new byte[16];
                using (var n = new AesCcm(k2))
                {
                    n.Encrypt(n2, p2, nct, ntag, aad);
                }

                using var c2 = new FipsAesCcm(k2);
                c2.SetNonce(n2);
                var r2 = c2.Encrypt(p2, aad);
                T.Bytes(nct, r2.Ciphertext, ".NET ciphertext");
                T.Bytes(ntag, r2.Tag, ".NET tag");
            });

            T.Run("Hash_DRBG SHA-256 (CAVS, no reseed) via the health-test service", () =>
            {
                byte[] entropyNonce = T.Hex("a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb" +
                                            "8581f9317517276e06e9607ddbcbcc2e");
                byte[] expected = T.Hex("d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80d" +
                                        "aaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febd" +
                                        "c343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51c" +
                                        "cde2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df");
                T.Bytes(expected, FipsRng.HealthTest(false, entropyNonce, null, expected.Length), "output");
            });
        }
    }
}
