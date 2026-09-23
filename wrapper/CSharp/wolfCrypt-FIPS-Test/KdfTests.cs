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
                T.Throws(FipsError.HMAC_MIN_KEYLEN_E,
                    () => FipsKdf.HkdfExtract(FipsHashType.Sha256, T.Hex("000102030405060708090a0b0c"), ikm),
                    "13-byte salt");
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

            T.Run("KDF calls restore the private key read gate", () => {
                FipsModule.SetPrivateKeyReadEnable(false);
                FipsKdf.Hkdf(FipsHashType.Sha256, new byte[32], null, null, 32);
                FipsKdf.Tls12Prf(FipsHashType.Sha256, new byte[48], "master secret", new byte[64], 48);
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

        private static HashAlgorithmName NetHash(FipsHashType h) => h switch {
            FipsHashType.Sha256 => HashAlgorithmName.SHA256,
            FipsHashType.Sha384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512
        };
    }
}
