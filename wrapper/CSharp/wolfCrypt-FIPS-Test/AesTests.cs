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

            T.Run("CBC chaining across calls equals one call", () =>
            {
                byte[] key = new byte[16], iv = new byte[16], msg = new byte[64];
                for (int i = 0; i < msg.Length; i++)
                {
                    msg[i] = (byte)i;
                }

                using var a = FipsAes.CreateCbc(key, iv, true);
                byte[] whole = a.Transform(msg);
                using var b = FipsAes.CreateCbc(key, iv, true);
                byte[] parts = b.Transform(msg.Take(32).ToArray()).Concat(b.Transform(msg.Skip(32).ToArray())).ToArray();
                T.Bytes(whole, parts, "chained");
            });

            T.Run("ECB and CBC reject partial blocks (module would truncate silently)", () =>
            {
                foreach (int len in new[] { 15, 20, 33 })
                {
                    using var cbc = FipsAes.CreateCbc(new byte[16], new byte[16], true);
                    using var ecb = FipsAes.CreateEcb(new byte[16], false);
                    foreach (var aes in new[] { cbc, ecb })
                    {
                        bool threw = false;
                        try { aes.Transform(new byte[len]); } catch (ArgumentException) { threw = true; }
                        T.True(threw, aes.Mode + " accepted " + len + " bytes");
                    }
                }
            });

            T.Run("CTR and OFB accept any length", () =>
            {
                using var ctr = FipsAes.CreateCtr(new byte[16], new byte[16]);
                using var ofb = FipsAes.CreateOfb(new byte[16], new byte[16], true);
                T.Equal(21, ctr.Transform(new byte[21]).Length, "CTR");
                T.Equal(21, ofb.Transform(new byte[21]).Length, "OFB");
            });

            T.Run("invalid key length is rejected", () =>
            {
                bool threw = false;
                try { FipsAes.CreateEcb(new byte[15], true).Dispose(); } catch (ArgumentException) { threw = true; }
                T.True(threw, "15-byte key accepted");
            });

            T.Run("CBC/OFB/CTR with DRBG-generated IV: fresh IV per object, round trip", () =>
            {
                using var rng = new FipsRng();
                byte[] key = new byte[16], msg = new byte[48];
                using var c1 = FipsAes.CreateCbc(key, rng);
                using var c2 = FipsAes.CreateCbc(key, rng);
                T.True(!c1.IV!.SequenceEqual(c2.IV!), "IV repeated");
                byte[] ct = c1.Transform(msg);
                using var dec = FipsAes.CreateCbcDecryptor(key, c1.IV!);
                T.Bytes(msg, dec.Transform(ct), "CBC round trip");
                using var ctr = FipsAes.CreateCtr(key, rng);
                using var ctrDec = FipsAes.CreateCtr(key, ctr.IV!);
                T.Bytes(msg, ctrDec.Transform(ctr.Transform(msg)), "CTR round trip");
                using var ofb = FipsAes.CreateOfb(key, rng);
                using var ofbDec = FipsAes.CreateOfb(key, ofb.IV!, false);
                T.Bytes(msg, ofbDec.Transform(ofb.Transform(msg)), "OFB round trip");
            });

            T.Run("SetIV: CBC decryptors only; refused on encryptors, OFB and CTR", () =>
            {
                using var rng = new FipsRng();
                byte[] key = new byte[16], iv1 = new byte[16], iv2 = Enumerable.Repeat((byte)0x5a, 16).ToArray();
                byte[] msg = new byte[32];
                byte[] ct1, ct2;
                using (var e1 = FipsAes.CreateCbc(key, iv1, true))
                {
                    ct1 = e1.Transform(msg);
                }

                using (var e2 = FipsAes.CreateCbc(key, iv2, true))
                {
                    ct2 = e2.Transform(msg);
                }

                using var dec = FipsAes.CreateCbcDecryptor(key, iv1);
                T.Bytes(msg, dec.Transform(ct1), "first message");
                dec.SetIV(iv2);
                T.Bytes(iv2, dec.IV!, "IV property updated");
                T.Bytes(msg, dec.Transform(ct2), "second message after SetIV");
                using var enc = FipsAes.CreateCbc(key, iv1, true);
                using var ofb = FipsAes.CreateOfb(key, new byte[16], true);
                using var ctr = FipsAes.CreateCtr(key, new byte[16]);
                using var drbgCbc = FipsAes.CreateCbc(key, rng);
                foreach (var a in new[] { enc, ofb, ctr, drbgCbc })
                {
                    bool threw = false;
                    try { a.SetIV(iv2); } catch (InvalidOperationException) { threw = true; }
                    T.True(threw, a.Mode + (a.Encrypting ? " encryptor" : "") + " SetIV allowed");
                }
                bool badKey = false;
                try { FipsAes.CreateCtr(new byte[20], new byte[16]).Dispose(); } catch (ArgumentException) { badKey = true; }
                T.True(badKey, "20-byte CTR key accepted");
            });

            T.Section("AES-GCM / GMAC");

            T.Run("GCM/GMAC internal IV below 96 bits is refused (IG C.H Scenario 2)", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                bool threw = false;
                try { gcm.UseInternalIV(rng, 8); } catch (ArgumentOutOfRangeException) { threw = true; }
                T.True(threw, "8-byte GCM IV accepted");
                threw = false;
                try { FipsGmac.Compute(new byte[16], new byte[4], rng, 8); } catch (ArgumentOutOfRangeException) { threw = true; }
                T.True(threw, "8-byte GMAC IV accepted");
                gcm.UseInternalIV(rng, 16);
                T.Equal(16, gcm.Encrypt(new byte[1]).IV.Length, "16-byte IV");
            });
            T.Run("GCM internal IV with a fixed field keeps at least 96 random bits", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                /* the module takes exactly 4 bytes; everything else is an
                 * ArgumentException from the wrapper, not BAD_FUNC_ARG */
                foreach (var (iv, ff) in new[] { (12, 4), (12, 1), (12, 0), (16, 5), (16, 0), (16, 1), (16, 2), (16, 3) })
                {
                    bool threw = false;
                    try { gcm.UseInternalIV(rng, iv, new byte[ff]); } catch (ArgumentException) { threw = true; }
                    T.True(threw, iv + "-byte IV with " + ff + "-byte fixed field accepted");
                }
                gcm.UseInternalIV(rng, 16, new byte[4]);
                T.Equal(16, gcm.Encrypt(new byte[1]).IV.Length, "16-byte IV, 4-byte fixed field");
                /* a refused re-selection leaves the working IV setup intact */
                try { gcm.UseInternalIV(rng, 16, new byte[2]); } catch (ArgumentException) { }
                T.Equal(16, gcm.Encrypt(new byte[1]).IV.Length, "still usable after a refused call");
            });
            T.Run("GCM UseInternalIV is once per object", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                gcm.UseInternalIV(rng);
                bool threw = false;
                try { gcm.UseInternalIV(rng, 16); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "second UseInternalIV accepted (would restart the IV sequence)");
            });

            T.Run("GCM refuses encryption past 2^32 invocations (SP 800-38D 8.3)", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                gcm.UseInternalIV(rng);
                gcm.Invocations = FipsAesGcm.MaxInvocations - 1;
                gcm.Encrypt(new byte[1]);   /* the 2^32nd */
                bool threw = false;
                try { gcm.Encrypt(new byte[1]); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "encryption 2^32 + 1 accepted");
            });

            /* Decrypt runs on its own native context, so a chosen-IV
             * ciphertext (even a forged one) cannot steer the next
             * encryption IV. */
            T.Run("GCM decryption never changes the encryption IV sequence", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                gcm.UseInternalIV(rng);
                var r1 = gcm.Encrypt(new byte[] { 1, 2, 3 });
                T.Bytes(new byte[] { 1, 2, 3 }, gcm.Decrypt(r1.IV, r1.Ciphertext, r1.Tag), "round trip");
                byte[] chosen = Enumerable.Repeat((byte)0x42, 12).ToArray();
                try { gcm.Decrypt(chosen, new byte[3], new byte[16]); } catch (WolfCryptFipsException) { }
                var r2 = gcm.Encrypt(new byte[] { 4, 5, 6 });
                var r3 = gcm.Encrypt(new byte[] { 7 });
                var ivs = new[] { r1.IV, r2.IV, r3.IV, chosen }.Select(Convert.ToHexString).ToList();
                T.Equal(4, ivs.Distinct().Count(), "an IV repeated");
            });

            T.Run("ACVP AES-GCM (external + internal IV, 8.2.1 + 8.2.2)", GcmVectors);
            T.Run("ACVP AES-GMAC (external + internal IV, 8.2.1 + 8.2.2)", GmacVectors);

            T.Run("GCM internal IV: fresh IV per encryption, round trip", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[32]);
                gcm.UseInternalIV(rng, 16, new byte[] { 1, 2, 3, 4 });
                byte[] pt = { 10, 20, 30 };
                var r1 = gcm.Encrypt(pt, new byte[] { 9 });
                var r2 = gcm.Encrypt(pt, new byte[] { 9 });
                T.Equal(16, r1.IV.Length, "IV size");
                T.True(r1.IV.Take(4).SequenceEqual(new byte[] { 1, 2, 3, 4 }), "fixed field");
                T.True(!r1.IV.SequenceEqual(r2.IV), "IV reused");
                T.Bytes(pt, gcm.Decrypt(r2.IV, r2.Ciphertext, r2.Tag, new byte[] { 9 }), "round trip");
            });

            /* the module draws the first IV from the DRBG, then adds one per encryption */
            T.Run("GCM internal IVs: DRBG start value, then previous IV plus one", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                gcm.UseInternalIV(rng);
                byte[] iv1 = gcm.Encrypt(new byte[1]).IV, iv2 = gcm.Encrypt(new byte[1]).IV;
                var n1 = new System.Numerics.BigInteger(iv1, isUnsigned: true, isBigEndian: true);
                var n2 = new System.Numerics.BigInteger(iv2, isUnsigned: true, isBigEndian: true);
                T.True(n2 == (n1 + 1) % System.Numerics.BigInteger.Pow(2, 96), "second IV is the first plus one");
            });

            T.Run("GCM invocation count is not charged for refused arguments", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                gcm.UseInternalIV(rng);
                gcm.Invocations = FipsAesGcm.MaxInvocations - 1;
                bool nullRefused = false, tagRefused = false;
                try { gcm.Encrypt(null!); } catch (ArgumentNullException) { nullRefused = true; }
                try { gcm.Encrypt(new byte[1], null, 8); } catch (ArgumentOutOfRangeException) { tagRefused = true; }
                T.True(nullRefused && tagRefused, "bad arguments accepted");
                T.Equal(FipsAesGcm.MaxInvocations - 1, gcm.Invocations, "counter charged for refused calls");
                gcm.Encrypt(new byte[1]);   /* the last allowed encryption */
            });

            T.Run("GCM Encrypt without UseInternalIV is refused", () =>
            {
                using var gcm = new FipsAesGcm(new byte[16]);
                bool threw = false;
                try { gcm.Encrypt(new byte[1]); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "encrypt allowed without IV source");
            });

            T.Run("GCM and GMAC refuse truncated or unexpected-length tags", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                gcm.UseInternalIV(rng);
                var r = gcm.Encrypt(new byte[] { 1, 2, 3 });
                foreach (int len in new[] { 1, 8, 15 })
                {
                    byte[] cut = r.Tag.Take(len).ToArray();
                    bool threw = false;
                    try { gcm.Decrypt(r.IV, r.Ciphertext, cut); } catch (ArgumentException) { threw = true; }
                    T.True(threw, len + "-byte GCM tag accepted");
                }
                bool threw12 = false;
                try { gcm.Decrypt(r.IV, r.Ciphertext, r.Tag, null, 12); } catch (ArgumentException) { threw12 = true; }
                T.True(threw12, "16-byte tag accepted where 12 expected");
                var gm = FipsGmac.Compute(new byte[16], new byte[] { 7 }, rng);
                bool threwGmac = false;
                try { FipsGmac.Verify(new byte[16], gm.IV, new byte[] { 7 }, gm.Tag.Take(1).ToArray()); }
                catch (ArgumentException) { threwGmac = true; }
                T.True(threwGmac, "1-byte GMAC tag accepted");
                T.True(FipsGmac.Verify(new byte[16], gm.IV, new byte[] { 7 }, gm.Tag), "full GMAC tag");
            });

            T.Run("GCM encrypt and GMAC compute refuse tags outside 12-16 bytes", () =>
            {
                using var rng = new FipsRng();
                using var gcm = new FipsAesGcm(new byte[16]);
                gcm.UseInternalIV(rng);
                foreach (int ts in new[] { 8, 11, 17 })
                {
                    bool e = false, g = false;
                    try { gcm.Encrypt(new byte[1], null, ts); } catch (ArgumentOutOfRangeException) { e = true; }
                    try { FipsGmac.Compute(new byte[16], new byte[1], rng, 12, ts); } catch (ArgumentOutOfRangeException) { g = true; }
                    T.True(e && g, "tag " + ts + " accepted");
                }
            });

            T.Run("GCM modified tag fails with AES_GCM_AUTH_E", () =>
            {
                using var gcm = new FipsAesGcm(new byte[16]);
                var r = gcm.EncryptWithIV(new byte[12], new byte[] { 1, 2, 3 });
                r.Tag[0] ^= 1;
                T.Throws(FipsError.AES_GCM_AUTH_E, () => gcm.Decrypt(r.IV, r.Ciphertext, r.Tag), "tampered tag");
            });

            T.Section("AES-CCM");
            T.Run("ACVP AES-CCM", CcmVectors);

            T.Run("CCM nonce advances per encryption, round trip", () =>
            {
                using var ccm = new FipsAesCcm(new byte[16]);
                ccm.SetNonce(new byte[12]);
                var r1 = ccm.Encrypt(new byte[] { 1, 2, 3 });
                var r2 = ccm.Encrypt(new byte[] { 1, 2, 3 });
                T.True(!r1.IV.SequenceEqual(r2.IV), "nonce reused");
                T.Bytes(new byte[] { 1, 2, 3 }, ccm.Decrypt(r2.IV, r2.Ciphertext, r2.Tag), "round trip");
            });

            T.Run("CCM tags below 64 bits are refused", () =>
            {
                using var ccm = new FipsAesCcm(new byte[16]);
                ccm.SetNonce(new byte[12]);
                foreach (int ts in new[] { 4, 6, 9 })
                {
                    bool threw = false;
                    try { ccm.Encrypt(new byte[1], null, ts); } catch (ArgumentOutOfRangeException) { threw = true; }
                    T.True(threw, "tag " + ts + " accepted");
                }
            });

            T.Run("CCM payload length limited by nonce size (13-byte nonce: < 65536 bytes)", () =>
            {
                byte[] nonce = new byte[13];
                using var ccm = new FipsAesCcm(new byte[16]);
                ccm.SetNonce(nonce);
                var ok = ccm.Encrypt(new byte[65535]);
                T.Equal(65535, ccm.Decrypt(ok.IV, ok.Ciphertext, ok.Tag).Length, "65535 bytes round trip");
                foreach (int len in new[] { 65536, 1048592 })
                {
                    bool threwE = false, threwD = false;
                    try { ccm.Encrypt(new byte[len]); } catch (ArgumentException) { threwE = true; }
                    try { ccm.Decrypt(nonce, new byte[len], new byte[16]); } catch (ArgumentException) { threwD = true; }
                    T.True(threwE && threwD, len + " bytes accepted");
                }
            });

            T.Run("CCM modified tag fails with AES_CCM_AUTH_E", () =>
            {
                using var ccm = new FipsAesCcm(new byte[16]);
                ccm.SetNonce(new byte[12]);
                var r = ccm.Encrypt(new byte[] { 1, 2, 3 });
                r.Tag[0] ^= 1;
                T.Throws(FipsError.AES_CCM_AUTH_E, () => ccm.Decrypt(r.IV, r.Ciphertext, r.Tag), "tampered tag");
            });

            T.Run("CCM SetNonce is once per object; DRBG nonce overload", () =>
            {
                using var ccm = new FipsAesCcm(new byte[16]);
                byte[] n = new byte[12];
                ccm.SetNonce(n);
                ccm.Encrypt(new byte[] { 1 });
                bool threw = false;
                try { ccm.SetNonce(n); } catch (InvalidOperationException) { threw = true; }
                T.True(threw, "second SetNonce accepted (would restart the nonce sequence)");
                using var rng = new FipsRng();
                using var c2 = new FipsAesCcm(new byte[16]);
                c2.SetNonce(rng);
                var r1 = c2.Encrypt(new byte[] { 4, 5 });
                var r2 = c2.Encrypt(new byte[] { 4, 5 });
                T.Equal(FipsAesCcm.DefaultNonceSize, r1.IV.Length, "nonce size");
                T.True(!r1.IV.SequenceEqual(new byte[12]), "DRBG nonce is all zeros");
                T.True(!r1.IV.SequenceEqual(r2.IV), "nonce reused");
                T.Bytes(new byte[] { 4, 5 }, c2.Decrypt(r2.IV, r2.Ciphertext, r2.Tag), "round trip");
                using var c3 = new FipsAesCcm(new byte[16]);
                threw = false;
                try { c3.SetNonce(rng, 6); } catch (ArgumentOutOfRangeException) { threw = true; }
                T.True(threw, "6-byte nonce accepted");
            });

            T.Run("GMAC Verify throws on bad arguments, false only on tag mismatch", () =>
            {
                using var rng = new FipsRng();
                byte[] key = new byte[16], aad = { 1, 2, 3 };
                var r = FipsGmac.Compute(key, aad, rng);
                T.True(FipsGmac.Verify(key, r.IV, aad, r.Tag), "valid tag");
                byte[] bad = (byte[])r.Tag.Clone(); bad[0] ^= 1;
                T.True(!FipsGmac.Verify(key, r.IV, aad, bad), "modified tag accepted");
                bool threw = false;
                try { FipsGmac.Verify(new byte[15], r.IV, aad, r.Tag); } catch (ArgumentException) { threw = true; }
                T.True(threw, "15-byte key reported as a tag mismatch");
                threw = false;
                try { FipsGmac.Verify(key, Array.Empty<byte>(), aad, r.Tag); } catch (ArgumentException) { threw = true; }
                T.True(threw, "empty IV reported as a tag mismatch");
            });

            T.Run("CCM Decrypt checks the nonce length before the payload bound", () =>
            {
                using var ccm = new FipsAesCcm(new byte[16]);
                foreach (int n in new[] { 6, 14, 15, 16, 24 })
                {
                    string? param = null;
                    try { ccm.Decrypt(new byte[n], new byte[32], new byte[16]); } catch (ArgumentException e) { param = e.ParamName; }
                    T.Equal("nonce", param, n + "-byte nonce");
                }
            });

            T.Run("CCM Decrypt refuses a tag of other than the expected length", () =>
            {
                using var ccm = new FipsAesCcm(new byte[16]);
                ccm.SetNonce(new byte[12]);
                var r8 = ccm.Encrypt(new byte[] { 7 }, null, 8);
                bool threw = false;
                try { ccm.Decrypt(r8.IV, r8.Ciphertext, r8.Tag); } catch (ArgumentException) { threw = true; }
                T.True(threw, "8-byte tag accepted when 16 is expected");
                T.Bytes(new byte[] { 7 }, ccm.Decrypt(r8.IV, r8.Ciphertext, r8.Tag, null, 8), "explicit 8-byte tag size");
            });
        }

        /* ---- ECB / CBC / OFB / CTR ---- */

        private static void BlockVectors(string alg, FipsAesMode mode)
        {
            int aft = 0, mct = 0;
            foreach (AcvpVectorSet set in Acvp.Load(alg))
            {
                foreach (var g in set.Groups)
                {
                    string tt = g.GetProperty("testType").GetString()!;
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    foreach (var t in g.GetProperty("tests").EnumerateArray())
                    {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key");
                        byte[]? iv = mode == FipsAesMode.Ecb ? null : Acvp.Hex(t, "iv");
                        byte[] input = Acvp.Hex(t, enc ? "pt" : "ct");
                        if (tt == "MCT")
                        {
                            Mct(mode, enc, key, iv, input, exp.GetProperty("resultsArray"), where);
                            mct++;
                        }
                        else
                        {
                            using var aes = Create(mode, key, iv, enc);
                            T.Bytes(Acvp.Hex(exp, enc ? "ct" : "pt"), aes.Transform(input), where);
                            aft++;
                        }
                    }
                }
            }
            Console.WriteLine("        " + alg + ": " + aft + " AFT/CTR, " + mct + " MCT (x100)");
        }

        private static FipsAes Create(FipsAesMode mode, byte[] key, byte[]? iv, bool enc) => mode switch
        {
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
            for (int i = 0; i < 100; i++)
            {
                string at = where + " MCT i=" + i;
                T.Bytes(Acvp.Hex(res[i], "key"), key, at + " key");
                if (iv != null)
                {
                    T.Bytes(Acvp.Hex(res[i], "iv"), iv, at + " iv");
                }

                T.Bytes(Acvp.Hex(res[i], enc ? "pt" : "ct"), input, at + " input");

                byte[] prev = Array.Empty<byte>(), last = Array.Empty<byte>();
                using (var aes = Create(mode, key, iv, enc))
                {
                    byte[] cur = input;
                    for (int j = 0; j < 1000; j++)
                    {
                        byte[] outp = aes.Transform(cur);
                        if (mode == FipsAesMode.Ecb)
                        {
                            cur = outp;                      /* PT[j+1] = CT[j] */
                        }
                        else
                        {
                            cur = j == 0 ? iv! : last;       /* PT[j+1] = IV or CT[j-1] */
                        }

                        prev = last;
                        last = outp;
                    }
                }
                T.Bytes(Acvp.Hex(res[i], enc ? "ct" : "pt"), last, at + " output");

                /* Key[i+1] = Key[i] XOR rightmost keylen bits of (out[998] || out[999]) */
                byte[] both = prev.Concat(last).ToArray();
                byte[] tail = both.Skip(both.Length - key.Length).ToArray();
                key = key.Zip(tail, (a, b) => (byte)(a ^ b)).ToArray();
                if (mode == FipsAesMode.Ecb)
                {
                    input = last;
                }
                else
                {
                    iv = last;
                    input = prev;
                }
            }
        }

        /* ---- GCM / GMAC ---- */

        private static readonly byte[] FixedField = { (byte)'w', (byte)'o', (byte)'l', (byte)'f' };

        private static void GcmVectors()
        {
            int ext = 0, intEnc = 0, dec = 0, refusedShortIv = 0;
            using var rng = new FipsRng();
            foreach (AcvpVectorSet set in Acvp.Load("ACVP-AES-GCM"))
            {
                foreach (var g in set.Groups)
                {
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    bool internalIv = g.GetProperty("ivGen").GetString() == "internal";
                    bool deterministic = g.GetProperty("ivGenMode").GetString() == "8.2.1";
                    int ivLen = g.GetProperty("ivLen").GetInt32() / 8;
                    int tagLen = g.GetProperty("tagLen").GetInt32() / 8;
                    foreach (var t in g.GetProperty("tests").EnumerateArray())
                    {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key"), aad = Acvp.Hex(t, "aad");
                        using var gcm = new FipsAesGcm(key);
                        if (enc && !internalIv)
                        {
                            var r = gcm.EncryptWithIV(Acvp.Hex(t, "iv"), Acvp.Hex(t, "pt"), aad, tagLen);
                            T.Bytes(Acvp.Hex(exp, "ct"), r.Ciphertext, where + " ct");
                            T.Bytes(Acvp.Hex(exp, "tag"), r.Tag, where + " tag");
                            ext++;
                        }
                        else if (enc)
                        {
                            /* Module-generated IV: output cannot match the
                             * recorded run. Check the module output round
                             * trips, and that the recorded response decrypts
                             * under the recorded IV. */
                            byte[] pt = Acvp.Hex(t, "pt");
                            int random = ivLen - (deterministic ? FixedField.Length : 0);
                            if (ivLen < 12 || random < FipsAesGcm.MinRandomIVSize)
                            {
                                /* IG C.H Scenario 2: internal IVs, and their
                                 * random part, >= 96 bits; the wrapper
                                 * refuses shorter ones. The recorded
                                 * response still decrypts. */
                                bool refused = false;
                                try { gcm.UseInternalIV(rng, ivLen, deterministic ? FixedField : null); }
                                catch (ArgumentException) { refused = true; }
                                T.True(refused, where + " internal IV with < 96 random bits accepted");
                                T.Bytes(pt, gcm.Decrypt(Acvp.Hex(exp, "iv"), Acvp.Hex(exp, "ct"), Acvp.Hex(exp, "tag"), aad, tagLen),
                                        where + " recorded response");
                                refusedShortIv++;
                                continue;
                            }
                            gcm.UseInternalIV(rng, ivLen, deterministic ? FixedField : null);
                            var r = gcm.Encrypt(pt, aad, tagLen);
                            T.Equal(ivLen, r.IV.Length, where + " iv length");
                            T.Bytes(pt, gcm.Decrypt(r.IV, r.Ciphertext, r.Tag, aad, tagLen), where + " round trip");
                            T.Bytes(pt, gcm.Decrypt(Acvp.Hex(exp, "iv"), Acvp.Hex(exp, "ct"), Acvp.Hex(exp, "tag"), aad, tagLen),
                                    where + " recorded response");
                            intEnc++;
                        }
                        else
                        {
                            DecryptCheck(() => gcm.Decrypt(Acvp.Hex(t, "iv"), Acvp.Hex(t, "ct"), Acvp.Hex(t, "tag"), aad, tagLen),
                                         exp, FipsError.AES_GCM_AUTH_E, where);
                            dec++;
                        }
                    }
                }
            }
            Console.WriteLine("        GCM: " + ext + " external-IV encrypt, " + intEnc + " internal-IV encrypt, " + dec +
                              " decrypt, " + refusedShortIv + " internal IV with < 96 random bits refused");
        }

        private static void GmacVectors()
        {
            int ext = 0, intEnc = 0, ver = 0;
            using var rng = new FipsRng();
            foreach (AcvpVectorSet set in Acvp.Load("ACVP-AES-GMAC"))
            {
                foreach (var g in set.Groups)
                {
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    bool internalIv = g.GetProperty("ivGen").GetString() == "internal";
                    int ivLen = g.GetProperty("ivLen").GetInt32() / 8;
                    int tagLen = g.GetProperty("tagLen").GetInt32() / 8;
                    foreach (var t in g.GetProperty("tests").EnumerateArray())
                    {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key"), aad = Acvp.Hex(t, "aad");
                        if (enc && !internalIv)
                        {
                            using var gcm = new FipsAesGcm(key);
                            var r = gcm.EncryptWithIV(Acvp.Hex(t, "iv"), Array.Empty<byte>(), aad, tagLen);
                            T.Bytes(Acvp.Hex(exp, "tag"), r.Tag, where);
                            ext++;
                        }
                        else if (enc && ivLen < 12)
                        {
                            bool refused = false;
                            try { FipsGmac.Compute(key, aad, rng, ivLen, tagLen); }
                            catch (ArgumentOutOfRangeException) { refused = true; }
                            T.True(refused, where + " 64-bit internal IV accepted");
                            T.True(FipsGmac.Verify(key, Acvp.Hex(exp, "iv"), aad, Acvp.Hex(exp, "tag"), tagLen),
                                   where + " recorded response");
                            intEnc++;
                        }
                        else if (enc)
                        {
                            var r = FipsGmac.Compute(key, aad, rng, ivLen, tagLen);
                            T.Equal(ivLen, r.IV.Length, where + " iv length");
                            T.True(FipsGmac.Verify(key, r.IV, aad, r.Tag, tagLen), where + " own tag");
                            T.True(FipsGmac.Verify(key, Acvp.Hex(exp, "iv"), aad, Acvp.Hex(exp, "tag"), tagLen),
                                   where + " recorded response");
                            intEnc++;
                        }
                        else
                        {
                            bool ok = FipsGmac.Verify(key, Acvp.Hex(t, "iv"), aad, Acvp.Hex(t, "tag"), tagLen);
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
            int e = 0, d = 0, shortTag = 0;
            foreach (AcvpVectorSet set in Acvp.Load("ACVP-AES-CCM"))
            {
                foreach (var g in set.Groups)
                {
                    bool enc = g.GetProperty("direction").GetString() == "encrypt";
                    int tagLen = g.GetProperty("tagLen").GetInt32() / 8;
                    foreach (var t in g.GetProperty("tests").EnumerateArray())
                    {
                        var exp = set.ExpectedFor(g, t);
                        string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                        byte[] key = Acvp.Hex(t, "key"), aad = Acvp.Hex(t, "aad"), nonce = Acvp.Hex(t, "iv");
                        using var ccm = new FipsAesCcm(key);
                        if (tagLen < FipsAesCcm.MinTagSize)
                        {
                            /* 32/48-bit tags are not offered by the wrapper */
                            bool refused = false;
                            try
                            {
                                if (enc) { ccm.SetNonce(nonce); ccm.Encrypt(Acvp.Hex(t, "pt"), aad, tagLen); }
                                else
                                {
                                    byte[] ct2 = Acvp.Hex(t, "ct");
                                    ccm.Decrypt(nonce, ct2.Take(ct2.Length - tagLen).ToArray(),
                                                ct2.Skip(ct2.Length - tagLen).ToArray(), aad, tagLen);
                                }
                            }
                            catch (ArgumentOutOfRangeException) { refused = true; }
                            T.True(refused, where + " short CCM tag accepted");
                            shortTag++;
                            continue;
                        }
                        if (enc)
                        {
                            ccm.SetNonce(nonce);
                            var r = ccm.Encrypt(Acvp.Hex(t, "pt"), aad, tagLen);
                            T.Bytes(Acvp.Hex(exp, "ct"), r.Ciphertext.Concat(r.Tag).ToArray(), where);
                            T.Bytes(nonce, r.IV, where + " nonce used");
                            e++;
                        }
                        else
                        {
                            byte[] ctTag = Acvp.Hex(t, "ct");
                            byte[] ct = ctTag.Take(ctTag.Length - tagLen).ToArray();
                            byte[] tag = ctTag.Skip(ctTag.Length - tagLen).ToArray();
                            DecryptCheck(() => ccm.Decrypt(nonce, ct, tag, aad, tagLen), exp, FipsError.AES_CCM_AUTH_E, where);
                            d++;
                        }
                    }
                }
            }
            Console.WriteLine("        CCM: " + e + " encrypt, " + d + " decrypt, " + shortTag + " 32/48-bit tag refused");
        }

        /* Expected is either {pt} (tag verifies) or {testPassed: false}. */
        private static void DecryptCheck(Func<byte[]> decrypt, JsonElement exp, int authError, string where)
        {
            bool shouldPass = !exp.TryGetProperty("testPassed", out var tp) || tp.GetBoolean();
            if (shouldPass)
            {
                T.Bytes(Acvp.Hex(exp, "pt"), decrypt(), where);
            }
            else
            {
                T.Throws(authError, () => decrypt(), where);
            }
        }
    }
}
