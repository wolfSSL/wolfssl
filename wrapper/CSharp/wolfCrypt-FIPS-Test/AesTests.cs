/* AesTests.cs
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
using System.Text.Json;

namespace wolfSSL.CSharp.Fips.Test
{
    internal static class AesTests
    {
        public static void Run()
        {
            T.Section("AES block modes");
            T.Run("ACVP AES-ECB (AFT + MCT)", () => BlockVectors("ACVP-AES-ECB", FipsAesMode.Ecb));
            T.Run("ACVP AES-CBC (AFT + MCT)", () => BlockVectors("ACVP-AES-CBC", FipsAesMode.Cbc));
            T.Run("ACVP AES-OFB (AFT + MCT)", () => BlockVectors("ACVP-AES-OFB", FipsAesMode.Ofb));
            T.Run("ACVP AES-CTR (AFT + counter)", () => BlockVectors("ACVP-AES-CTR", FipsAesMode.Ctr));

            T.Run("CBC chaining across calls equals one call", () => {
                byte[] key = new byte[16], iv = new byte[16], msg = new byte[64];
                for (int i = 0; i < msg.Length; i++) msg[i] = (byte)i;
                using var a = FipsAes.CreateCbc(key, iv, true);
                byte[] whole = a.Transform(msg);
                using var b = FipsAes.CreateCbc(key, iv, true);
                byte[] parts = b.Transform(msg.Take(32).ToArray()).Concat(b.Transform(msg.Skip(32).ToArray())).ToArray();
                T.Bytes(whole, parts, "chained");
            });

            T.Run("ECB and CBC reject partial blocks (module would truncate silently)", () => {
                foreach (int len in new[] { 15, 20, 33 }) {
                    using var cbc = FipsAes.CreateCbc(new byte[16], new byte[16], true);
                    using var ecb = FipsAes.CreateEcb(new byte[16], false);
                    foreach (var aes in new[] { cbc, ecb }) {
                        bool threw = false;
                        try { aes.Transform(new byte[len]); } catch (ArgumentException) { threw = true; }
                        T.True(threw, aes.Mode + " accepted " + len + " bytes");
                    }
                }
            });

            T.Run("CTR and OFB accept any length", () => {
                using var ctr = FipsAes.CreateCtr(new byte[16], new byte[16]);
                using var ofb = FipsAes.CreateOfb(new byte[16], new byte[16], true);
                T.Equal(21, ctr.Transform(new byte[21]).Length, "CTR");
                T.Equal(21, ofb.Transform(new byte[21]).Length, "OFB");
            });

            T.Run("invalid key length is rejected", () => {
                bool threw = false;
                try { FipsAes.CreateEcb(new byte[15], true).Dispose(); } catch (WolfCryptFipsException) { threw = true; }
                T.True(threw, "15-byte key accepted");
            });

            T.Section("AES-GCM / GMAC");
            T.Run("ACVP AES-GCM (external + internal IV, 8.2.1 + 8.2.2)", GcmVectors);
            T.Run("ACVP AES-GMAC (external + internal IV, 8.2.1 + 8.2.2)", GmacVectors);

            T.Run("GCM internal IV: fresh IV per encryption, round trip", () => {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[32]);
                gcm.UseInternalIV(rng, 12, new byte[] { 1, 2, 3, 4 });
                byte[] pt = { 10, 20, 30 };
                var r1 = gcm.Encrypt(pt, new byte[] { 9 });
                var r2 = gcm.Encrypt(pt, new byte[] { 9 });
                T.Equal(12, r1.IV.Length, "IV size");
                T.True(r1.IV.Take(4).SequenceEqual(new byte[] { 1, 2, 3, 4 }), "fixed field");
                T.True(!r1.IV.SequenceEqual(r2.IV), "IV reused");
                T.Bytes(pt, gcm.Decrypt(r2.IV, r2.Ciphertext, r2.Tag, new byte[] { 9 }), "round trip");
            });

            T.Run("GCM Encrypt without UseInternalIV is refused", () => {
                using var gcm = new FipsAesGcm(new byte[16]);
                bool threw = false;
                try { gcm.Encrypt(new byte[1]); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "encrypt allowed without IV source");
            });

            T.Run("GCM modified tag fails with AES_GCM_AUTH_E", () => {
                using var gcm = new FipsAesGcm(new byte[16]);
                var r = gcm.EncryptWithIV(new byte[12], new byte[] { 1, 2, 3 });
                r.Tag[0] ^= 1;
                T.Throws(FipsError.AES_GCM_AUTH_E, () => gcm.Decrypt(r.IV, r.Ciphertext, r.Tag), "tampered tag");
            });

            T.Section("AES-CCM");
            T.Run("ACVP AES-CCM", CcmVectors);

            T.Run("CCM nonce advances per encryption, round trip", () => {
                using var ccm = new FipsAesCcm(new byte[16]);
                ccm.SetNonce(new byte[12]);
                var r1 = ccm.Encrypt(new byte[] { 1, 2, 3 });
                var r2 = ccm.Encrypt(new byte[] { 1, 2, 3 });
                T.True(!r1.IV.SequenceEqual(r2.IV), "nonce reused");
                T.Bytes(new byte[] { 1, 2, 3 }, ccm.Decrypt(r2.IV, r2.Ciphertext, r2.Tag), "round trip");
            });

            T.Run("CCM modified tag fails with AES_CCM_AUTH_E", () => {
                using var ccm = new FipsAesCcm(new byte[16]);
                ccm.SetNonce(new byte[12]);
                var r = ccm.Encrypt(new byte[] { 1, 2, 3 });
                r.Tag[0] ^= 1;
                T.Throws(FipsError.AES_CCM_AUTH_E, () => ccm.Decrypt(r.IV, r.Ciphertext, r.Tag), "tampered tag");
            });
        }

        /* ---- ECB / CBC / OFB / CTR ---- */

        private static void BlockVectors(string alg, FipsAesMode mode)
        {
            int aft = 0, mct = 0;
            foreach (AcvpVectorSet set in Acvp.Load(alg)) {
                foreach (var g in set.Groups) {
                    string tt = g.GetProperty("testType").GetString()!;
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key");
                        byte[]? iv = mode == FipsAesMode.Ecb ? null : Acvp.Hex(t, "iv");
                        byte[] input = Acvp.Hex(t, enc ? "pt" : "ct");
                        if (tt == "MCT") {
                            Mct(mode, enc, key, iv, input, exp.GetProperty("resultsArray"), where);
                            mct++;
                        }
                        else {
                            using var aes = Create(mode, key, iv, enc);
                            T.Bytes(Acvp.Hex(exp, enc ? "ct" : "pt"), aes.Transform(input), where);
                            aft++;
                        }
                    }
                }
            }
            Console.WriteLine("        " + alg + ": " + aft + " AFT/CTR, " + mct + " MCT (x100)");
        }

        private static FipsAes Create(FipsAesMode mode, byte[] key, byte[]? iv, bool enc) => mode switch {
            FipsAesMode.Ecb => FipsAes.CreateEcb(key, enc),
            FipsAesMode.Cbc => FipsAes.CreateCbc(key, iv!, enc),
            FipsAesMode.Ofb => FipsAes.CreateOfb(key, iv!, enc),
            _ => FipsAes.CreateCtr(key, iv!)
        };

        /* AESAVS Monte Carlo test (ECB, CBC, OFB). */
        private static void Mct(FipsAesMode mode, bool enc, byte[] key, byte[]? iv, byte[] input,
                                JsonElement results, string where)
        {
            var res = results.EnumerateArray().ToList();
            for (int i = 0; i < 100; i++) {
                string at = where + " MCT i=" + i;
                T.Bytes(Acvp.Hex(res[i], "key"), key, at + " key");
                if (iv != null)
                    T.Bytes(Acvp.Hex(res[i], "iv"), iv, at + " iv");
                T.Bytes(Acvp.Hex(res[i], enc ? "pt" : "ct"), input, at + " input");

                byte[] prev = Array.Empty<byte>(), last = Array.Empty<byte>();
                using (var aes = Create(mode, key, iv, enc)) {
                    byte[] cur = input;
                    for (int j = 0; j < 1000; j++) {
                        byte[] outp = aes.Transform(cur);
                        if (mode == FipsAesMode.Ecb)
                            cur = outp;                      /* PT[j+1] = CT[j] */
                        else
                            cur = j == 0 ? iv! : last;       /* PT[j+1] = IV or CT[j-1] */
                        prev = last;
                        last = outp;
                    }
                }
                T.Bytes(Acvp.Hex(res[i], enc ? "ct" : "pt"), last, at + " output");

                /* Key[i+1] = Key[i] XOR rightmost keylen bits of (out[998] || out[999]) */
                byte[] both = prev.Concat(last).ToArray();
                byte[] tail = both.Skip(both.Length - key.Length).ToArray();
                key = key.Zip(tail, (a, b) => (byte)(a ^ b)).ToArray();
                if (mode == FipsAesMode.Ecb) {
                    input = last;
                }
                else {
                    iv = last;
                    input = prev;
                }
            }
        }

        /* ---- GCM / GMAC ---- */

        private static readonly byte[] FixedField = { (byte)'w', (byte)'o', (byte)'l', (byte)'f' };

        private static void GcmVectors()
        {
            int ext = 0, intEnc = 0, dec = 0;
            using var rng = new FipsRng();
            foreach (AcvpVectorSet set in Acvp.Load("ACVP-AES-GCM")) {
                foreach (var g in set.Groups) {
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    bool internalIv = g.GetProperty("ivGen").GetString() == "internal";
                    bool deterministic = g.GetProperty("ivGenMode").GetString() == "8.2.1";
                    int ivLen = g.GetProperty("ivLen").GetInt32() / 8;
                    int tagLen = g.GetProperty("tagLen").GetInt32() / 8;
                    foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key"), aad = Acvp.Hex(t, "aad");
                        using var gcm = new FipsAesGcm(key);
                        if (enc && !internalIv) {
                            var r = gcm.EncryptWithIV(Acvp.Hex(t, "iv"), Acvp.Hex(t, "pt"), aad, tagLen);
                            T.Bytes(Acvp.Hex(exp, "ct"), r.Ciphertext, where + " ct");
                            T.Bytes(Acvp.Hex(exp, "tag"), r.Tag, where + " tag");
                            ext++;
                        }
                        else if (enc) {
                            /* Module-generated IV: output cannot match the
                             * recorded run. Check the module output round
                             * trips, and that the recorded response decrypts
                             * under the recorded IV. */
                            byte[] pt = Acvp.Hex(t, "pt");
                            gcm.UseInternalIV(rng, ivLen, deterministic ? FixedField : null);
                            var r = gcm.Encrypt(pt, aad, tagLen);
                            T.Equal(ivLen, r.IV.Length, where + " iv length");
                            T.Bytes(pt, gcm.Decrypt(r.IV, r.Ciphertext, r.Tag, aad), where + " round trip");
                            T.Bytes(pt, gcm.Decrypt(Acvp.Hex(exp, "iv"), Acvp.Hex(exp, "ct"), Acvp.Hex(exp, "tag"), aad),
                                    where + " recorded response");
                            intEnc++;
                        }
                        else {
                            DecryptCheck(() => gcm.Decrypt(Acvp.Hex(t, "iv"), Acvp.Hex(t, "ct"), Acvp.Hex(t, "tag"), aad),
                                         exp, FipsError.AES_GCM_AUTH_E, where);
                            dec++;
                        }
                    }
                }
            }
            Console.WriteLine("        GCM: " + ext + " external-IV encrypt, " + intEnc + " internal-IV encrypt, " + dec + " decrypt");
        }

        private static void GmacVectors()
        {
            int ext = 0, intEnc = 0, ver = 0;
            using var rng = new FipsRng();
            foreach (AcvpVectorSet set in Acvp.Load("ACVP-AES-GMAC")) {
                foreach (var g in set.Groups) {
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    bool internalIv = g.GetProperty("ivGen").GetString() == "internal";
                    int ivLen = g.GetProperty("ivLen").GetInt32() / 8;
                    int tagLen = g.GetProperty("tagLen").GetInt32() / 8;
                    foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key"), aad = Acvp.Hex(t, "aad");
                        if (enc && !internalIv) {
                            using var gcm = new FipsAesGcm(key);
                            var r = gcm.EncryptWithIV(Acvp.Hex(t, "iv"), Array.Empty<byte>(), aad, tagLen);
                            T.Bytes(Acvp.Hex(exp, "tag"), r.Tag, where);
                            ext++;
                        }
                        else if (enc) {
                            var r = FipsGmac.Compute(key, aad, rng, ivLen, tagLen);
                            T.Equal(ivLen, r.IV.Length, where + " iv length");
                            T.True(FipsGmac.Verify(key, r.IV, aad, r.Tag), where + " own tag");
                            T.True(FipsGmac.Verify(key, Acvp.Hex(exp, "iv"), aad, Acvp.Hex(exp, "tag")),
                                   where + " recorded response");
                            intEnc++;
                        }
                        else {
                            bool ok = FipsGmac.Verify(key, Acvp.Hex(t, "iv"), aad, Acvp.Hex(t, "tag"));
                            T.Equal(exp.GetProperty("testPassed").GetBoolean(), ok, where);
                            ver++;
                        }
                    }
                }
            }
            Console.WriteLine("        GMAC: " + ext + " external-IV, " + intEnc + " internal-IV, " + ver + " verify");
        }

        /* ---- CCM ---- */

        private static void CcmVectors()
        {
            int e = 0, d = 0;
            foreach (AcvpVectorSet set in Acvp.Load("ACVP-AES-CCM")) {
                foreach (var g in set.Groups) {
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    int tagLen = g.GetProperty("tagLen").GetInt32() / 8;
                    foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key"), aad = Acvp.Hex(t, "aad"), nonce = Acvp.Hex(t, "iv");
                        using var ccm = new FipsAesCcm(key);
                        if (enc) {
                            ccm.SetNonce(nonce);
                            var r = ccm.Encrypt(Acvp.Hex(t, "pt"), aad, tagLen);
                            T.Bytes(Acvp.Hex(exp, "ct"), r.Ciphertext.Concat(r.Tag).ToArray(), where);
                            T.Bytes(nonce, r.IV, where + " nonce used");
                            e++;
                        }
                        else {
                            byte[] ctTag = Acvp.Hex(t, "ct");
                            byte[] ct = ctTag.Take(ctTag.Length - tagLen).ToArray();
                            byte[] tag = ctTag.Skip(ctTag.Length - tagLen).ToArray();
                            DecryptCheck(() => ccm.Decrypt(nonce, ct, tag, aad), exp, FipsError.AES_CCM_AUTH_E, where);
                            d++;
                        }
                    }
                }
            }
            Console.WriteLine("        CCM: " + e + " encrypt, " + d + " decrypt");
        }

        /* Expected is either {pt} (tag verifies) or {testPassed: false}. */
        private static void DecryptCheck(Func<byte[]> decrypt, JsonElement exp, int authError, string where)
        {
            bool shouldPass = !exp.TryGetProperty("testPassed", out var tp) || tp.GetBoolean();
            if (shouldPass)
                T.Bytes(Acvp.Hex(exp, "pt"), decrypt(), where);
            else
                T.Throws(authError, () => decrypt(), where);
        }
    }
}
