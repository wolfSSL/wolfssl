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

        private static void RequireTlsHash(FipsHashType h)
        {
            if (h != FipsHashType.Sha256 && h != FipsHashType.Sha384 && h != FipsHashType.Sha512)
                throw new NotSupportedException("TLS KDFs support SHA-256, SHA-384 and SHA-512");
        }

        /* An empty salt is passed as NULL. RFC 5869 treats an absent salt as
         * HashLen zero bytes, which is what the module does for NULL; a
         * non-NULL zero-length salt would instead be used as a zero-length
         * HMAC key and refused (HMAC_MIN_KEYLEN_E). HMAC zero-pads keys, so
         * the two are the same value. */
        private static byte[]? Salt(byte[]? salt) => salt == null || salt.Length == 0 ? null : salt;

        private static byte[] Run(string fn, int outLen, Func<byte[], int> call)
        {
            if (outLen <= 0)
                throw new ArgumentOutOfRangeException(nameof(outLen));
            byte[] output = new byte[outLen];
            WolfCryptFipsException.Check(fn, FipsModule.WithPrivateKeyRead(() => call(output)));
            return output;
        }

        /* ---- TLS 1.2 ---- */

        /* TLS 1.2 PRF (RFC 5246 section 5): PRF(secret, label, seed). */
        public static byte[] Tls12Prf(FipsHashType hash, byte[] secret, string label, byte[] seed, int outLen)
        {
            if (secret == null || label == null || seed == null)
                throw new ArgumentNullException();
            byte[] lab = Encoding.ASCII.GetBytes(label);
            return Run("wc_PRF_TLSv12_fips", outLen, o => Native.wc_PRF_TLSv12_fips(o, (uint)o.Length,
                secret, (uint)secret.Length, lab, (uint)lab.Length, seed, (uint)seed.Length,
                1, MacTypeOf(hash), IntPtr.Zero, INVALID_DEVID));
        }

        /* TLS 1.2 extended master secret (RFC 7627). */
        public static byte[] Tls12ExtendedMasterSecret(FipsHashType hash, byte[] preMasterSecret, byte[] sessionHash) =>
            Tls12Prf(hash, preMasterSecret, "extended master secret", sessionHash, 48);

        /* TLS 1.2 key block: PRF(master, "key expansion", server_random || client_random). */
        public static byte[] Tls12KeyBlock(FipsHashType hash, byte[] masterSecret, byte[] clientRandom,
                                           byte[] serverRandom, int length)
        {
            byte[] seed = new byte[serverRandom.Length + clientRandom.Length];
            serverRandom.CopyTo(seed, 0);
            clientRandom.CopyTo(seed, serverRandom.Length);
            return Tls12Prf(hash, masterSecret, "key expansion", seed, length);
        }

        /* P_hash without a label (wc_PRF). */
        public static byte[] PHash(FipsHashType hash, byte[] secret, byte[] seed, int outLen)
        {
            if (secret == null || seed == null)
                throw new ArgumentNullException();
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
         * zeros of the digest length. */
        public static byte[] Tls13Extract(FipsHashType hash, byte[]? salt, byte[] ikm)
        {
            if (ikm == null)
                throw new ArgumentNullException(nameof(ikm));
            RequireTlsHash(hash);
            salt = Salt(salt);
            byte[] ikmCopy = (byte[])ikm.Clone();   /* native parameter is non-const */
            return Run("wc_Tls13_HKDF_Extract_fips", FipsHash.DigestSizeOf(hash), o =>
                Native.wc_Tls13_HKDF_Extract_fips(o, salt, salt == null ? 0 : salt.Length,
                    ikmCopy, ikmCopy.Length, (int)hash));
        }

        /* HKDF-Expand-Label(secret, label, context, length) with the
         * "tls13 " protocol prefix. */
        public static byte[] Tls13ExpandLabel(FipsHashType hash, byte[] secret, string label, byte[] context,
                                              int outLen, string protocol = "tls13 ")
        {
            if (secret == null || label == null || context == null)
                throw new ArgumentNullException();
            RequireTlsHash(hash);
            byte[] proto = Encoding.ASCII.GetBytes(protocol), lab = Encoding.ASCII.GetBytes(label);
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
                throw new ArgumentNullException();
            if (keyId < 'A' || keyId > 'F')
                throw new ArgumentOutOfRangeException(nameof(keyId));
            return Run("wc_SSH_KDF_fips", outLen, o => Native.wc_SSH_KDF_fips((byte)hash, (byte)keyId,
                o, (uint)o.Length, k, (uint)k.Length, h, (uint)h.Length, sessionId, (uint)sessionId.Length));
        }
    }
}
