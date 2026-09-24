/* FipsKdf.cs
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
using System.Security.Cryptography;
using System.Text;

namespace wolfSSL.CSharp.Fips
{
    /* Key derivation functions from the FIPS module: TLS 1.2 PRF, HKDF,
     * the TLS 1.3 HKDF primitives and the SSH KDF (SP 800-135, RFC 5869).
     *
     * The module gates KDF output behind the per-thread private key read
     * enable; each call here enables it for the duration of the call and
     * restores it (see FipsModule.WithPrivateKeyRead). */
    public static class FipsKdf
    {
        private const int INVALID_DEVID = -2;

        /* The PRF functions take the TLS MAC algorithm ids (hash.h:
         * sha256_mac = 4, sha384_mac = 5, sha512_mac = 6), not wc_HashType. */
        private static int MacTypeOf(FipsHashType h) => h switch {
            FipsHashType.Sha256 => 4,
            FipsHashType.Sha384 => 5,
            FipsHashType.Sha512 => 6,
            _ => throw new NotSupportedException("TLS PRF supports SHA-256, SHA-384 and SHA-512")
        };

        /* TLS 1.3 cipher suites use SHA-256 and SHA-384; the module accepts
         * SHA-512 only when built with WOLFSSL_TLS13_SHA512. */
        private static void RequireTls13Hash(FipsHashType h)
        {
            if (h != FipsHashType.Sha256 && h != FipsHashType.Sha384)
                throw new NotSupportedException("TLS 1.3 KDFs support SHA-256 and SHA-384");
        }

        /* An empty salt is passed as NULL. RFC 5869 treats an absent salt as
         * HashLen zero bytes, which is what the module does for NULL; a
         * non-NULL zero-length salt would instead be used as a zero-length
         * HMAC key and refused (HMAC_MIN_KEYLEN_E). HMAC zero-pads keys, so
         * the two are the same value. */
        private static byte[]? Salt(byte[]? salt) => salt == null || salt.Length == 0 ? null : salt;

        /* MAX_TLS13_HKDF_LABEL_SZ of the loaded library (47 + its
         * WC_MAX_DIGEST_SIZE), from the size helper. */
        private static int tls13LabelMax;
        internal static int Tls13LabelMax
        {
            get {
                if (tls13LabelMax == 0)
                    tls13LabelMax = FipsObject.StructSize(FipsStructType.Tls13LabelMax);
                return tls13LabelMax;
            }
        }

        private static byte[] Run(string fn, int outLen, Func<byte[], int> call)
        {
            if (outLen <= 0)
                throw new ArgumentOutOfRangeException(nameof(outLen));
            byte[] output = new byte[outLen];
            int ret = FipsModule.WithPrivateKeyRead(() => call(output));
            if (ret != 0) {
                CryptographicOperations.ZeroMemory(output);
                throw new WolfCryptFipsException(fn, ret);
            }
            return output;
        }

        /* ---- TLS 1.2 ---- */

        /* TLS 1.2 PRF (RFC 5246 section 5): PRF(secret, label, seed).
         *
         * The TLS 1.2 KDF is approved only with the extended master secret
         * (FIPS 140-3 IG D.Q, RFC 7627), so the RFC 5246 "master secret"
         * derivation is refused: use Tls12ExtendedMasterSecret for the
         * master secret and Tls12KeyBlock for the key block. */
        public static byte[] Tls12Prf(FipsHashType hash, byte[] secret, string label, byte[] seed, int outLen)
        {
            if (secret == null || label == null || seed == null)
                throw new ArgumentNullException(secret == null ? nameof(secret) : label == null ? nameof(label) : nameof(seed));
            byte[] lab = Ascii(label, nameof(label));
            if (StartsWithMasterSecret(lab, seed))
                throw new ArgumentException("the non-EMS TLS 1.2 master secret derivation is not approved " +
                    "(IG D.Q); use Tls12ExtendedMasterSecret", nameof(label));
            return Run("wc_PRF_TLSv12_fips", outLen, o => Native.wc_PRF_TLSv12_fips(o, (uint)o.Length,
                secret, (uint)secret.Length, lab, (uint)lab.Length, seed, (uint)seed.Length,
                1, MacTypeOf(hash), IntPtr.Zero, INVALID_DEVID));
        }

        /* The module PRF hashes label || seed as one string, so the refusal
         * applies to that concatenation: splitting "master secret" between
         * label and seed (or passing it in the seed) derives the same
         * non-EMS master secret. "extended master secret" does not start
         * with it. */
        private static bool StartsWithMasterSecret(byte[] label, byte[] seed)
        {
            ReadOnlySpan<byte> ms = "master secret"u8;
            int n = Math.Min(ms.Length, label.Length);
            if (!label.AsSpan(0, n).SequenceEqual(ms.Slice(0, n)))
                return false;
            return label.Length >= ms.Length || seed.AsSpan().StartsWith(ms.Slice(label.Length));
        }

        /* TLS 1.2 extended master secret (RFC 7627). */
        public static byte[] Tls12ExtendedMasterSecret(FipsHashType hash, byte[] preMasterSecret, byte[] sessionHash) =>
            Tls12Prf(hash, preMasterSecret, "extended master secret", sessionHash, 48);

        /* TLS 1.2 key block: PRF(master, "key expansion", server_random || client_random). */
        public static byte[] Tls12KeyBlock(FipsHashType hash, byte[] masterSecret, byte[] clientRandom,
                                           byte[] serverRandom, int length)
        {
            if (clientRandom == null || serverRandom == null)
                throw new ArgumentNullException(clientRandom == null ? nameof(clientRandom) : nameof(serverRandom));
            byte[] seed = new byte[serverRandom.Length + clientRandom.Length];
            serverRandom.CopyTo(seed, 0);
            clientRandom.CopyTo(seed, serverRandom.Length);
            return Tls12Prf(hash, masterSecret, "key expansion", seed, length);
        }

        /* P_hash without a label (wc_PRF). Internal: it can build any TLS 1.2
         * PRF derivation, including the non-approved non-EMS master secret;
         * used by the tests to check the PRF core. */
        internal static byte[] PHash(FipsHashType hash, byte[] secret, byte[] seed, int outLen)
        {
            if (secret == null || seed == null)
                throw new ArgumentNullException(secret == null ? nameof(secret) : nameof(seed));
            return Run("wc_PRF_fips", outLen, o => Native.wc_PRF_fips(o, (uint)o.Length,
                secret, (uint)secret.Length, seed, (uint)seed.Length, MacTypeOf(hash), IntPtr.Zero, INVALID_DEVID));
        }

        /* ---- HKDF (RFC 5869) ---- */

        public static byte[] HkdfExtract(FipsHashType hash, byte[]? salt, byte[] ikm)
        {
            if (ikm == null)
                throw new ArgumentNullException(nameof(ikm));
            salt = Salt(salt);
            return Run("wc_HKDF_Extract_fips", FipsHash.DigestSizeOf(hash), o => Native.wc_HKDF_Extract_fips(
                (int)hash, salt, salt == null ? 0u : (uint)salt.Length, ikm, (uint)ikm.Length, o));
        }

        public static byte[] HkdfExpand(FipsHashType hash, byte[] prk, byte[]? info, int outLen)
        {
            if (prk == null)
                throw new ArgumentNullException(nameof(prk));
            return Run("wc_HKDF_Expand_fips", outLen, o => Native.wc_HKDF_Expand_fips(
                (int)hash, prk, (uint)prk.Length, info, info == null ? 0u : (uint)info.Length, o, (uint)o.Length));
        }

        public static byte[] Hkdf(FipsHashType hash, byte[] ikm, byte[]? salt, byte[]? info, int outLen)
        {
            if (ikm == null)
                throw new ArgumentNullException(nameof(ikm));
            salt = Salt(salt);
            return Run("wc_HKDF_fips", outLen, o => Native.wc_HKDF_fips((int)hash, ikm, (uint)ikm.Length,
                salt, salt == null ? 0u : (uint)salt.Length, info, info == null ? 0u : (uint)info.Length,
                o, (uint)o.Length));
        }

        /* ---- TLS 1.3 (RFC 8446 section 7.1) ---- */

        /* HKDF-Extract as used by TLS 1.3. An empty ikm means a string of
         * zeros of the digest length (RFC 8446 7.1). That string is passed
         * explicitly: for ikmLen == 0 the v5.2.x module writes HashLen zero
         * bytes into the ikm buffer, which a zero-length array cannot hold. */
        public static byte[] Tls13Extract(FipsHashType hash, byte[]? salt, byte[] ikm)
        {
            if (ikm == null)
                throw new ArgumentNullException(nameof(ikm));
            RequireTls13Hash(hash);
            salt = Salt(salt);
            int n = FipsHash.DigestSizeOf(hash);
            /* native parameter is non-const: never hand it the caller's array */
            byte[] ikmCopy = ikm.Length == 0 ? new byte[n] : (byte[])ikm.Clone();
            try {
                return Run("wc_Tls13_HKDF_Extract_fips", n, o =>
                    Native.wc_Tls13_HKDF_Extract_fips(o, salt, salt == null ? 0 : salt.Length,
                        ikmCopy, ikmCopy.Length, (int)hash));
            }
            finally {
                CryptographicOperations.ZeroMemory(ikmCopy);
            }
        }

        /* HKDF-Expand-Label(secret, label, context, length) with the
         * "tls13 " protocol prefix. */
        public static byte[] Tls13ExpandLabel(FipsHashType hash, byte[] secret, string label, byte[] context,
                                              int outLen, string protocol = "tls13 ")
        {
            if (secret == null || label == null || context == null)
                throw new ArgumentNullException(secret == null ? nameof(secret) : label == null ? nameof(label) : nameof(context));
            RequireTls13Hash(hash);
            byte[] proto = Ascii(protocol, nameof(protocol)), lab = Ascii(label, nameof(label));
            /* The v5.2.x module builds the HkdfLabel in a fixed stack buffer
             * (MAX_TLS13_HKDF_LABEL_SZ) without a capacity check, and stores
             * the label and context lengths in single bytes. */
            if (proto.Length + lab.Length > 255)
                throw new ArgumentException("protocol + label must be at most 255 bytes", nameof(label));
            if (context.Length > 255)
                throw new ArgumentException("context must be at most 255 bytes", nameof(context));
            if (4 + proto.Length + lab.Length + context.Length > Tls13LabelMax)
                throw new ArgumentException("HkdfLabel would exceed the module's " + Tls13LabelMax +
                                            "-byte buffer", nameof(context));
            return Run("wc_Tls13_HKDF_Expand_Label_fips", outLen, o => Native.wc_Tls13_HKDF_Expand_Label_fips(
                o, (uint)o.Length, secret, (uint)secret.Length, proto, (uint)proto.Length,
                lab, (uint)lab.Length, context, (uint)context.Length, (int)hash));
        }

        /* ---- SSH (RFC 4253 section 7.2) ---- */

        /* keyId is 'A' to 'F'. k is the shared secret as an unsigned
         * big-endian integer (encoded as an mpint by the module); h is the
         * exchange hash. */
        public static byte[] SshKdf(FipsHashType hash, char keyId, byte[] k, byte[] h, byte[] sessionId, int outLen)
        {
            if (k == null || h == null || sessionId == null)
                throw new ArgumentNullException(k == null ? nameof(k) : h == null ? nameof(h) : nameof(sessionId));
            if (keyId < 'A' || keyId > 'F')
                throw new ArgumentOutOfRangeException(nameof(keyId));
            /* The module encodes k as an mpint but only adds the sign byte;
             * it does not remove redundant leading zeros (RFC 4251 5), so
             * strip them here (for example a fixed-width ECDH secret). */
            int skip = 0;
            while (skip < k.Length - 1 && k[skip] == 0)
                skip++;
            byte[] kNorm = skip > 0 ? k.AsSpan(skip).ToArray() : k;
            try {
                return Run("wc_SSH_KDF_fips", outLen, o => Native.wc_SSH_KDF_fips((byte)hash, (byte)keyId,
                    o, (uint)o.Length, kNorm, (uint)kNorm.Length, h, (uint)h.Length, sessionId, (uint)sessionId.Length));
            }
            finally {
                if (skip > 0)
                    CryptographicOperations.ZeroMemory(kNorm);   /* our copy only, never the caller's */
            }
        }

        /* Labels are ASCII. Encoding.ASCII would replace other characters
         * with '?', so distinct labels could derive the same keys; refuse
         * them instead. */
        private static byte[] Ascii(string s, string name)
        {
            if (s == null)
                throw new ArgumentNullException(name);
            foreach (char c in s)
                if (c > 0x7F)
                    throw new ArgumentException(name + " must be ASCII", name);
            return Encoding.ASCII.GetBytes(s);
        }
    }
}
