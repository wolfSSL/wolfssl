/* KdfTests.cs
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
    internal static class KdfTests
    {
        private static readonly FipsHashType[] TlsHashes =
            { FipsHashType.Sha256, FipsHashType.Sha384, FipsHashType.Sha512 };

        public static void Run()
        {
            T.Section("KDFs");

            T.Run("ACVP TLS-v1.2 KDF (RFC 7627 extended master secret + key block)", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("TLS-v1.2"))
                    foreach (var g in set.Groups) {
                        FipsHashType h = EccDhTests.HashOf(g.GetProperty("hashAlg").GetString()!);
                        int kbLen = g.GetProperty("keyBlockLength").GetInt32() / 8;
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            var exp = set.ExpectedFor(g, t);
                            string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                            byte[] ms = FipsKdf.Tls12ExtendedMasterSecret(h, Acvp.Hex(t, "preMasterSecret"),
                                                                          Acvp.Hex(t, "sessionHash"));
                            T.Bytes(Acvp.Hex(exp, "masterSecret"), ms, where + " master secret");
                            T.Bytes(Acvp.Hex(exp, "keyBlock"), FipsKdf.Tls12KeyBlock(h, ms,
                                Acvp.Hex(t, "clientRandom"), Acvp.Hex(t, "serverRandom"), kbLen), where + " key block");
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " vectors");
            });

            T.Run("ACVP TLS-v1.3 KDF (RFC 8446 key schedule, PSK / DHE / PSK-DHE)", () => {
                int n = 0;
                foreach (AcvpVectorSet set in Acvp.Load("TLS-v1.3"))
                    foreach (var g in set.Groups) {
                        FipsHashType h = EccDhTests.HashOf(g.GetProperty("hmacAlg").GetString()!);
                        foreach (var t in g.GetProperty("tests").EnumerateArray()) {
                            var exp = set.ExpectedFor(g, t);
                            string where = set.File + " tcId " + t.GetProperty("tcId").GetInt32();
                            var got = Tls13Schedule(h, Opt(t, "psk"), Opt(t, "dhe"),
                                Acvp.Hex(t, "helloClientRandom"), Acvp.Hex(t, "helloServerRandom"),
                                Acvp.Hex(t, "finishedServerRandom"), Acvp.Hex(t, "finishedClientRandom"));
                            foreach (var (name, value) in got)
                                T.Bytes(Acvp.Hex(exp, name), value, where + " " + name);
                            n++;
                        }
                    }
                Console.WriteLine("        " + n + " vectors");
            });

            /* The salt is the HMAC key of HKDF-Extract; the module applies the
             * 112-bit HMAC minimum to it. RFC 5869 test case 1 (13-byte salt)
             * is therefore refused. An empty salt is allowed (zeros of the
             * hash length are used). */
            T.Run("HKDF salt of 1-13 bytes is refused (HMAC_MIN_KEYLEN_E)", () => {
                byte[] ikm = Enumerable.Repeat((byte)0x0b, 22).ToArray();
                for (int s = 1; s <= 13; s++) {
                    byte[] salt = Enumerable.Range(1, s).Select(i => (byte)i).ToArray();
                    T.Throws(FipsError.HMAC_MIN_KEYLEN_E,
                        () => FipsKdf.HkdfExtract(FipsHashType.Sha256, salt, ikm), s + "-byte salt");
                }
                T.Equal(32, FipsKdf.HkdfExtract(FipsHashType.Sha256, new byte[14], ikm).Length, "14-byte salt");
            });

            T.Run("HKDF RFC 5869 test case 3 (SHA-256, empty salt), matches .NET", () => {
                byte[] ikm = Enumerable.Repeat((byte)0x0b, 22).ToArray();
                byte[] prk = FipsKdf.HkdfExtract(FipsHashType.Sha256, null, ikm);
                byte[] okm = FipsKdf.Hkdf(FipsHashType.Sha256, ikm, null, null, 42);
                T.Bytes(T.Hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), prk, "PRK");
                T.Bytes(T.Hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
                        okm, "OKM");
                T.Bytes(HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 42), okm, ".NET OKM");
                T.Bytes(FipsKdf.HkdfExpand(FipsHashType.Sha256, prk, null, 42), okm, "expand");
                T.Bytes(okm, FipsKdf.Hkdf(FipsHashType.Sha256, ikm, Array.Empty<byte>(), null, 42), "empty salt = no salt");
            });

            foreach (FipsHashType fh in TlsHashes) {
                FipsHashType h = fh;
                T.Run("HKDF " + h + " matches .NET HKDF", () => {
                    HashAlgorithmName nh = NetHash(h);
                    using var rng = new FipsRng();
                    for (int i = 0; i < 20; i++) {
                        /* salt empty or >= 14 bytes (see the HMAC minimum test) */
                        byte[] ikm = rng.Generate(16 + i), salt = rng.Generate(i == 0 ? 0 : 13 + i),
                               info = rng.Generate(i % 7);
                        int len = 1 + i * 13;
                        T.Bytes(HKDF.DeriveKey(nh, ikm, len, salt, info),
                                FipsKdf.Hkdf(h, ikm, salt, info, len), "iteration " + i);
                        T.Bytes(HKDF.Extract(nh, ikm, salt), FipsKdf.HkdfExtract(h, salt, ikm), "extract " + i);
                    }
                });
            }

            foreach (FipsHashType fh in new[] { FipsHashType.Sha1, FipsHashType.Sha256, FipsHashType.Sha512 }) {
                FipsHashType h = fh;
                T.Run("SSH KDF " + h + " matches RFC 4253 reference", () => {
                    using var rng = new FipsRng();
                    byte[] hh = rng.Generate(FipsHash.DigestSizeOf(h)), sid = rng.Generate(FipsHash.DigestSizeOf(h));
                    for (int i = 0; i < 12; i++) {
                        byte[] k = rng.Generate(32 + i);
                        k[0] = (byte)(i % 2 == 0 ? 0x80 | k[0] : (k[0] & 0x7f) | 1);  /* both mpint pad cases */
                        char id = (char)('A' + i % 6);
                        int len = 16 + i * 11;
                        T.Bytes(SshReference(h, id, k, hh, sid, len), FipsKdf.SshKdf(h, id, k, hh, sid, len),
                                "key " + id + " len " + len);
                    }
                });
            }

            /* Regression: an empty IKM must equal HashLen zero bytes and must
             * not reach the module as ikmLen 0 (the v5.2.x module then writes
             * HashLen bytes into the buffer). Runs without ACVP vectors. */
            T.Run("TLS 1.3 extract: empty IKM equals HashLen zeros (SHA-256/384)", () => {
                foreach (FipsHashType h in new[] { FipsHashType.Sha256, FipsHashType.Sha384 }) {
                    int n = FipsHash.DigestSizeOf(h);
                    for (int i = 0; i < 50; i++) {
                        T.Bytes(HKDF.Extract(NetHash(h), new byte[n], Array.Empty<byte>()),
                                FipsKdf.Tls13Extract(h, null, Array.Empty<byte>()), h + " empty IKM vs .NET HKDF");
                    }
                    byte[] ikm = { 1, 2, 3 };
                    FipsKdf.Tls13Extract(h, new byte[n], ikm);
                    T.Bytes(new byte[] { 1, 2, 3 }, ikm, h + " caller IKM unchanged");
                }
            });

            T.Run("TLS 1.3 KDFs refuse hashes other than SHA-256 and SHA-384", () => {
                bool threw = false;
                try { FipsKdf.Tls13Extract(FipsHashType.Sha512, null, new byte[64]); } catch (NotSupportedException) { threw = true; }
                T.True(threw, "SHA-512 accepted");
            });

            T.Run("TLS 1.3 expand-label: HkdfLabel limited to the module buffer and 255-byte fields", () => {
                int max = FipsKdf.Tls13LabelMax;
                Console.WriteLine("        module HkdfLabel buffer: " + max + " bytes");
                byte[] secret = new byte[32];
                int ctxAtMax = max - 4 - 6 - 7;     /* "tls13 " + "derived" */
                T.Equal(32, FipsKdf.Tls13ExpandLabel(FipsHashType.Sha256, secret, "derived", new byte[ctxAtMax], 32).Length,
                        "at the limit");
                foreach (var (label, ctx, what) in new[] {
                        ("derived", ctxAtMax + 1, "one byte over"),
                        (new string('a', 250), 0, "protocol + label over 255"),
                        ("x", 256, "context over 255"),
                        (new string('a', 128), 32, "128-byte label") }) {
                    bool threw = false;
                    try { FipsKdf.Tls13ExpandLabel(FipsHashType.Sha256, secret, label, new byte[ctx], 32); }
                    catch (ArgumentException) { threw = true; }
                    T.True(threw, what + " accepted");
                }
            });

            T.Run("SSH KDF: leading zero bytes of K are not significant", () => {
                using var rng = new FipsRng();
                byte[] hh = rng.Generate(32), sid = rng.Generate(32);
                byte[] k = rng.Generate(31); k[0] |= 0x01;
                byte[] expected = SshReference(FipsHashType.Sha256, 'C', k, hh, sid, 40);
                foreach (int zeros in new[] { 1, 3 }) {
                    byte[] padded = new byte[zeros].Concat(k).ToArray();
                    T.Bytes(expected, FipsKdf.SshKdf(FipsHashType.Sha256, 'C', padded, hh, sid, 40), zeros + " leading zeros");
                }
            });

            T.Run("P_hash (TLS 1.2 PRF core) matches an HMAC reference (SHA-256/384/512)", () => {
                using var rng = new FipsRng();
                foreach (FipsHashType h in new[] { FipsHashType.Sha256, FipsHashType.Sha384, FipsHashType.Sha512 }) {
                    for (int i = 0; i < 5; i++) {
                        byte[] secret = rng.Generate(48), seed = rng.Generate(13 + i);
                        int len = 20 + i * 37;
                        T.Bytes(PHashReference(h, secret, seed, len), FipsKdf.PHash(h, secret, seed, len), h + " len " + len);
                    }
                }
            });

            /* Output checks that run without the ACVP vectors: label || seed
             * concatenation, EMS label, key block seed order (server random
             * first) and the MAC id mapping for each hash. */
            T.Run("TLS 1.2 PRF, EMS and key block match the RFC 5246 / 7627 reference", () => {
                using var rng = new FipsRng();
                foreach (FipsHashType h in new[] { FipsHashType.Sha256, FipsHashType.Sha384, FipsHashType.Sha512 }) {
                    byte[] pms = rng.Generate(48), sessionHash = rng.Generate(FipsHash.DigestSizeOf(h));
                    byte[] cr = rng.Generate(32), sr = rng.Generate(32);
                    byte[] ms = FipsKdf.Tls12ExtendedMasterSecret(h, pms, sessionHash);
                    T.Bytes(PrfReference(h, pms, "extended master secret", sessionHash, 48), ms, h + " EMS");
                    T.Bytes(PrfReference(h, ms, "key expansion", sr.Concat(cr).ToArray(), 104),
                            FipsKdf.Tls12KeyBlock(h, ms, cr, sr, 104), h + " key block (server || client)");
                    byte[] vd = rng.Generate(FipsHash.DigestSizeOf(h));
                    T.Bytes(PrfReference(h, ms, "client finished", vd, 12),
                            FipsKdf.Tls12Prf(h, ms, "client finished", vd, 12), h + " finished");
                }
            });

            T.Run("TLS 1.2 non-EMS \"master secret\" derivation is refused (IG D.Q)", () => {
                bool threw = false;
                try { FipsKdf.Tls12Prf(FipsHashType.Sha256, new byte[48], "master secret", new byte[64], 48); }
                catch (ArgumentException) { threw = true; }
                T.True(threw, "non-EMS master secret derived");
                /* the module PRF sees label || seed, so every split of
                 * "master secret" between them is the same derivation */
                byte[] randoms = new byte[64];
                foreach (int cut in new[] { 0, 1, 6, 7, 12 }) {
                    string lab = "master secret".Substring(0, cut);
                    byte[] seed = Encoding.ASCII.GetBytes("master secret".Substring(cut)).Concat(randoms).ToArray();
                    threw = false;
                    try { FipsKdf.Tls12Prf(FipsHashType.Sha256, new byte[48], lab, seed, 48); }
                    catch (ArgumentException) { threw = true; }
                    T.True(threw, "split \"" + lab + "\" + seed accepted");
                }
                /* labels that only share a prefix, or seeds that differ, are fine */
                FipsKdf.Tls12Prf(FipsHashType.Sha256, new byte[48], "master", Encoding.ASCII.GetBytes(" key").Concat(randoms).ToArray(), 48);
                FipsKdf.Tls12Prf(FipsHashType.Sha256, new byte[48], "", randoms, 48);
            });

            T.Run("TLS 1.3 Expand-Label matches .NET HKDF-Expand over an RFC 8446 HkdfLabel", () => {
                using var rng = new FipsRng();
                foreach (FipsHashType h in new[] { FipsHashType.Sha256, FipsHashType.Sha384 }) {
                    int hl = FipsHash.DigestSizeOf(h);
                    foreach (var (label, ctxLen, outLen) in new[] { ("derived", hl, hl), ("key", 0, 16), ("iv", 0, 12),
                                                                    ("c hs traffic", hl, hl), ("finished", 0, hl) }) {
                        byte[] secret = rng.Generate(hl), ctx = rng.Generate(ctxLen);
                        byte[] lab = Encoding.ASCII.GetBytes("tls13 " + label);
                        byte[] info = new byte[] { (byte)(outLen >> 8), (byte)outLen, (byte)lab.Length }
                            .Concat(lab).Append((byte)ctx.Length).Concat(ctx).ToArray();
                        T.Bytes(HKDF.Expand(NetHash(h), secret, outLen, info),
                                FipsKdf.Tls13ExpandLabel(h, secret, label, ctx, outLen), h + " " + label);
                    }
                }
            });

            T.Run("KDF calls restore the private key read gate", () => {
                FipsModule.SetPrivateKeyReadEnable(false);
                FipsKdf.Hkdf(FipsHashType.Sha256, new byte[32], null, null, 32);
                FipsKdf.Tls12ExtendedMasterSecret(FipsHashType.Sha256, new byte[48], new byte[32]);
                T.True(!FipsModule.PrivateKeyReadEnabled, "gate left enabled");
            });

            T.Run("Tls12KeyBlock names a null random", () => {
                bool threw = false;
                try { FipsKdf.Tls12KeyBlock(FipsHashType.Sha256, new byte[48], null!, new byte[32], 40); }
                catch (ArgumentNullException e) { threw = e.ParamName == "clientRandom"; }
                T.True(threw, "null clientRandom not reported by name");
            });

            T.Run("KDF labels must be ASCII (no lossy '?' substitution)", () => {
                bool threw = false;
                try { FipsKdf.Tls13ExpandLabel(FipsHashType.Sha256, new byte[32], "cl\u00e9", new byte[32], 32); }
                catch (ArgumentException) { threw = true; }
                T.True(threw, "non-ASCII TLS 1.3 label accepted");
                threw = false;
                try { FipsKdf.Tls12Prf(FipsHashType.Sha256, new byte[48], "cl\u00e9", new byte[64], 48); }
                catch (ArgumentException) { threw = true; }
                T.True(threw, "non-ASCII TLS 1.2 label accepted");
                T.True(!FipsModule.PrivateKeyReadEnabled, "gate left enabled");
            });

            T.Run("TLS PRF rejects non-TLS hashes", () => {
                bool threw = false;
                try { FipsKdf.Tls12Prf(FipsHashType.Sha3_256, new byte[48], "x", new byte[1], 16); }
                catch (NotSupportedException) { threw = true; }
                T.True(threw, "SHA3 accepted");
            });
        }

        /* RFC 8446 section 7.1, arranged as the ACVP TLS 1.3 KDF test
         * defines the transcript (hello and finished randoms). */
        private static (string, byte[])[] Tls13Schedule(FipsHashType h, byte[] psk, byte[] dhe,
            byte[] hcr, byte[] hsr, byte[] fsr, byte[] fcr)
        {
            int n = FipsHash.DigestSizeOf(h);
            byte[] H(params byte[][] parts) => FipsHash.Compute(h, parts.SelectMany(p => p).ToArray());
            byte[] L(byte[] secret, string label, byte[] ctx) => FipsKdf.Tls13ExpandLabel(h, secret, label, ctx, n);

            byte[] early = FipsKdf.Tls13Extract(h, null, psk);
            byte[] ce = L(early, "c e traffic", H(hcr));
            byte[] eexp = L(early, "e exp master", H(hcr));
            byte[] salt = L(early, "derived", H());
            byte[] hs = FipsKdf.Tls13Extract(h, salt, dhe.Length > 0 ? dhe : new byte[n]);
            byte[] chs = L(hs, "c hs traffic", H(hcr, hsr));
            byte[] shs = L(hs, "s hs traffic", H(hcr, hsr));
            salt = L(hs, "derived", H());
            byte[] ms = FipsKdf.Tls13Extract(h, salt, new byte[n]);
            byte[] cap = L(ms, "c ap traffic", H(hcr, hsr, fsr));
            byte[] sap = L(ms, "s ap traffic", H(hcr, hsr, fsr));
            byte[] exp = L(ms, "exp master", H(hcr, hsr, fsr));
            byte[] res = L(ms, "res master", H(hcr, hsr, fsr, fcr));
            return new[] {
                ("clientEarlyTrafficSecret", ce), ("earlyExporterMasterSecret", eexp),
                ("clientHandshakeTrafficSecret", chs), ("serverHandshakeTrafficSecret", shs),
                ("clientApplicationTrafficSecret", cap), ("serverApplicationTrafficSecret", sap),
                ("exporterMasterSecret", exp), ("resumptionMasterSecret", res)
            };
        }

        /* RFC 4253 7.2: K1 = HASH(mpint(K) || H || X || session_id),
         * Kn = HASH(mpint(K) || H || K1 || ... || Kn-1). Test reference only. */
        private static byte[] SshReference(FipsHashType h, char id, byte[] k, byte[] hh, byte[] sid, int len)
        {
            byte[] kk = k.SkipWhile(b => b == 0).ToArray();
            if ((kk[0] & 0x80) != 0) kk = new byte[] { 0 }.Concat(kk).ToArray();
            byte[] mp = BitConverter.GetBytes(kk.Length).Reverse().Concat(kk).ToArray();
            Func<byte[], byte[]> hash = h switch {
                FipsHashType.Sha1 => SHA1.HashData, FipsHashType.Sha256 => SHA256.HashData,
                _ => SHA512.HashData };
            byte[] outp = hash(mp.Concat(hh).Append((byte)id).Concat(sid).ToArray());
            while (outp.Length < len)
                outp = outp.Concat(hash(mp.Concat(hh).Concat(outp).ToArray())).ToArray();
            return outp.Take(len).ToArray();
        }

        /* PSK-only groups omit "dhe" and DHE-only groups omit "psk". */
        private static byte[] Opt(System.Text.Json.JsonElement t, string name) =>
            t.TryGetProperty(name, out _) ? Acvp.Hex(t, name) : Array.Empty<byte>();

        /* RFC 5246 5: P_hash(secret, seed) = HMAC(secret, A(1) + seed) || ...,
         * A(0) = seed, A(i) = HMAC(secret, A(i-1)). Test reference only. */
        private static byte[] PHashReference(FipsHashType h, byte[] secret, byte[] seed, int len)
        {
            Func<byte[], byte[], byte[]> hmac = h switch {
                FipsHashType.Sha256 => HMACSHA256.HashData,
                FipsHashType.Sha384 => HMACSHA384.HashData,
                _ => HMACSHA512.HashData
            };
            var outp = new System.Collections.Generic.List<byte>();
            byte[] a = seed;
            while (outp.Count < len) {
                a = hmac(secret, a);
                outp.AddRange(hmac(secret, a.Concat(seed).ToArray()));
            }
            return outp.Take(len).ToArray();
        }

        /* PRF(secret, label, seed) = P_hash(secret, label || seed). */
        private static byte[] PrfReference(FipsHashType h, byte[] secret, string label, byte[] seed, int len) =>
            PHashReference(h, secret, Encoding.ASCII.GetBytes(label).Concat(seed).ToArray(), len);

        private static HashAlgorithmName NetHash(FipsHashType h) => h switch {
            FipsHashType.Sha256 => HashAlgorithmName.SHA256,
            FipsHashType.Sha384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512
        };
    }
}
