/* FipsRsa.cs
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

namespace wolfSSL.CSharp.Fips
{
    public enum FipsRsaPadding
    {
        /* RSAES-PKCS1-v1_5. Not approved for key transport after 2023 under
         * SP 800-131A Rev. 2; provided for interoperability. */
        Pkcs1v15 = 0,
        /* RSAES-OAEP (SP 800-56B) */
        Oaep = 1
    }

    /* Public RSA key components (big-endian). */
    public sealed class FipsRsaPublicKey
    {
        public byte[] Modulus { get; }
        public byte[] Exponent { get; }
        internal FipsRsaPublicKey(byte[] n, byte[] e) { Modulus = n; Exponent = e; }
    }

    /* Full RSA key components (big-endian). */
    public sealed class FipsRsaKeyComponents
    {
        public byte[] E { get; }
        public byte[] N { get; }
        public byte[] D { get; }
        public byte[] P { get; }
        public byte[] Q { get; }
        internal FipsRsaKeyComponents(byte[] e, byte[] n, byte[] d, byte[] p, byte[] q)
        { E = e; N = n; D = d; P = p; Q = q; }
    }

    /* RSA key pair generated inside the FIPS module, with signature and
     * encryption services.
     *
     * The v5.2.3 boundary has no RSA key import, so keys can only be created
     * with Generate. Export (wc_RsaExportKey_fips) returns all components
     * and is gated by FipsModule.SetPrivateKeyReadEnable on the calling
     * thread. */
    public sealed class FipsRsaKey : FipsObject
    {
        public const long DefaultExponent = 65537;
        private bool initialized;

        /* Modulus size in bytes (signature / ciphertext size). */
        public int Size { get; }
        public int Bits => Size * 8;

        private FipsRsaKey(int bits, long exponent, FipsRng rng) : base(FipsStructType.Rsa)
        {
            int ret = Native.wc_InitRsaKey_fips(Handle, IntPtr.Zero);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_InitRsaKey_fips", ret);
            }
            initialized = true;
            rng.ThrowIfDisposed();
            ret = Native.wc_MakeRsaKey_fips(Handle, bits, exponent, rng.Handle);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_MakeRsaKey_fips", ret);
            }
            Size = Native.wc_RsaEncryptSize_fips(Handle);
        }

        /* Modulus sizes approved for key generation (FIPS 186-5,
         * SP 800-131A Rev. 2; cert #4718 Security Policy Table 7). */
        public static readonly int[] ApprovedKeySizes = { 2048, 3072, 4096 };

        /* Generates a key pair (FIPS 186 key generation, includes the
         * module's pairwise consistency test).
         *
         * The size is checked here: the v5.2.1 and v5.2.3 modules also
         * accept 1024 (bug 6367, RsaSizeCheck), which is disallowed. */
        public static FipsRsaKey Generate(int bits, FipsRng rng, long exponent = DefaultExponent)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            if (Array.IndexOf(ApprovedKeySizes, bits) < 0)
                throw new ArgumentException("RSA key size must be 2048, 3072 or 4096 bits", nameof(bits));
            return new FipsRsaKey(bits, exponent, rng);
        }

        /* Validates the key (wc_CheckRsaKey_fips). */
        public void Check()
        {
            ThrowIfDisposed();
            WolfCryptFipsException.Check("wc_CheckRsaKey_fips", Native.wc_CheckRsaKey_fips(Handle));
        }

        /* Exports all key components. Requires the private key read gate
         * to be enabled on this thread (FIPS_PRIVATE_KEY_LOCKED_E otherwise). */
        public FipsRsaKeyComponents Export()
        {
            ThrowIfDisposed();
            byte[] e = new byte[8], n = new byte[Size], d = new byte[Size],
                   p = new byte[Size], q = new byte[Size];
            uint eSz = (uint)e.Length, nSz = (uint)n.Length, dSz = (uint)d.Length,
                 pSz = (uint)p.Length, qSz = (uint)q.Length;
            WolfCryptFipsException.Check("wc_RsaExportKey_fips",
                Native.wc_RsaExportKey_fips(Handle, e, ref eSz, n, ref nSz, d, ref dSz, p, ref pSz, q, ref qSz));
            var result = new FipsRsaKeyComponents(e.Take((int)eSz).ToArray(), n.Take((int)nSz).ToArray(),
                d.Take((int)dSz).ToArray(), p.Take((int)pSz).ToArray(), q.Take((int)qSz).ToArray());
            CryptographicOperations.ZeroMemory(d);
            CryptographicOperations.ZeroMemory(p);
            CryptographicOperations.ZeroMemory(q);
            return result;
        }

        /* Public components. The module exports the key as a whole, so this
         * also requires the private key read gate on this thread; private
         * components are zeroed immediately. */
        public FipsRsaPublicKey ExportPublic()
        {
            FipsRsaKeyComponents c = Export();
            CryptographicOperations.ZeroMemory(c.D);
            CryptographicOperations.ZeroMemory(c.P);
            CryptographicOperations.ZeroMemory(c.Q);
            return new FipsRsaPublicKey(c.N, c.E);
        }

        /* ---- PKCS#1 v1.5 signatures (RSASSA-PKCS1-v1_5) ---- */

        /* Signs a message digest. digest must be the hash of the message
         * with the given algorithm; the DigestInfo encoding is added here. */
        public byte[] SignPkcs1v15(FipsHashType hash, byte[] digest, FipsRng rng)
        {
            byte[] di = DigestInfo(hash, digest);
            byte[] sig = new byte[Size];
            rng.ThrowIfDisposed();
            ThrowIfDisposed();
            int ret = Native.wc_RsaSSL_Sign_fips(di, (uint)di.Length, sig, (uint)sig.Length, Handle, rng.Handle);
            if (ret < 0)
                throw new WolfCryptFipsException("wc_RsaSSL_Sign_fips", ret);
            return sig.Take(ret).ToArray();
        }

        public bool VerifyPkcs1v15(FipsHashType hash, byte[] digest, byte[] signature)
        {
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            byte[] expected = DigestInfo(hash, digest);
            byte[] recovered = new byte[Size];
            ThrowIfDisposed();
            int ret = Native.wc_RsaSSL_Verify_fips(signature, (uint)signature.Length, recovered,
                                                   (uint)recovered.Length, Handle);
            if (ret < 0)
                return VerifyFailure("wc_RsaSSL_Verify_fips", ret);
            return CryptographicOperations.FixedTimeEquals(expected, recovered.AsSpan(0, ret));
        }

        /* ---- PSS signatures (RSASSA-PSS) ---- */

        /* saltLen -1 = digest length (RSA_PSS_SALT_LEN_DEFAULT). SHA-3 is
         * not supported for MGF1 in this module. */
        public byte[] SignPss(FipsHashType hash, byte[] digest, FipsRng rng, int saltLen = -1)
        {
            CheckDigest(hash, digest);
            byte[] sig = new byte[Size];
            rng.ThrowIfDisposed();
            ThrowIfDisposed();
            int ret = Native.wc_RsaPSS_SignEx_fips(digest, (uint)digest.Length, sig, (uint)sig.Length,
                (int)hash, Mgf(hash), saltLen, Handle, rng.Handle);
            if (ret < 0)
                throw new WolfCryptFipsException("wc_RsaPSS_SignEx_fips", ret);
            return sig.Take(ret).ToArray();
        }

        public bool VerifyPss(FipsHashType hash, byte[] digest, byte[] signature, int saltLen = -1)
        {
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            CheckDigest(hash, digest);
            ThrowIfDisposed();
            byte[] decoded = new byte[Size];
            int ret = Native.wc_RsaPSS_VerifyEx_fips((byte[])signature.Clone(), (uint)signature.Length,
                decoded, (uint)decoded.Length, (int)hash, Mgf(hash), saltLen, Handle);
            if (ret < 0)
                return VerifyFailure("wc_RsaPSS_VerifyEx_fips", ret);
            ret = Native.wc_RsaPSS_CheckPaddingEx_fips(digest, (uint)digest.Length, decoded, (uint)ret,
                (int)hash, saltLen, Bits);
            if (FipsError.IsModuleStateError(ret))
                throw new WolfCryptFipsException("wc_RsaPSS_CheckPaddingEx_fips", ret);
            return ret == 0;
        }

        /* ---- encryption ---- */

        public byte[] Encrypt(byte[] plaintext, FipsRng rng, FipsRsaPadding padding = FipsRsaPadding.Oaep,
                              FipsHashType oaepHash = FipsHashType.Sha256, byte[]? label = null)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            rng.ThrowIfDisposed();
            ThrowIfDisposed();
            byte[] ct = new byte[Size];
            int ret = Native.wc_RsaPublicEncryptEx_fips(plaintext, (uint)plaintext.Length, ct, (uint)ct.Length,
                Handle, rng.Handle, (int)padding, PadHash(padding, oaepHash), PadMgf(padding, oaepHash),
                label, label == null ? 0u : (uint)label.Length);
            if (ret < 0)
                throw new WolfCryptFipsException("wc_RsaPublicEncryptEx_fips", ret);
            return ct.Take(ret).ToArray();
        }

        public byte[] Decrypt(byte[] ciphertext, FipsRsaPadding padding = FipsRsaPadding.Oaep,
                              FipsHashType oaepHash = FipsHashType.Sha256, byte[]? label = null)
        {
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));
            ThrowIfDisposed();
            byte[] pt = new byte[Size];
            int ret = Native.wc_RsaPrivateDecryptEx_fips(ciphertext, (uint)ciphertext.Length, pt, (uint)pt.Length,
                Handle, (int)padding, PadHash(padding, oaepHash), PadMgf(padding, oaepHash),
                label, label == null ? 0u : (uint)label.Length);
            if (ret < 0)
                throw new WolfCryptFipsException("wc_RsaPrivateDecryptEx_fips", ret);
            byte[] result = pt.Take(ret).ToArray();
            CryptographicOperations.ZeroMemory(pt);
            return result;
        }

        /* ---- helpers ---- */

        /* Module errors that mean "signature does not verify" are reported
         * as false; FIPS state errors are thrown. */
        private static bool VerifyFailure(string fn, int ret)
        {
            if (FipsError.IsModuleStateError(ret))
                throw new WolfCryptFipsException(fn, ret);
            return false;
        }

        private static int PadHash(FipsRsaPadding p, FipsHashType h) => p == FipsRsaPadding.Oaep ? (int)h : 0;
        private static int PadMgf(FipsRsaPadding p, FipsHashType h) => p == FipsRsaPadding.Oaep ? Mgf(h) : 0;

        /* MGF1 identifiers from rsa.h */
        private static int Mgf(FipsHashType h) => h switch {
            FipsHashType.Sha1 => 26,
            FipsHashType.Sha224 => 4,
            FipsHashType.Sha256 => 1,
            FipsHashType.Sha384 => 2,
            FipsHashType.Sha512 => 3,
            _ => throw new NotSupportedException("MGF1 with " + h + " is not supported by this module")
        };

        private static void CheckDigest(FipsHashType hash, byte[] digest)
        {
            if (digest == null)
                throw new ArgumentNullException(nameof(digest));
            if (digest.Length != FipsHash.DigestSizeOf(hash))
                throw new ArgumentException("digest length does not match " + hash, nameof(digest));
        }

        /* DER DigestInfo prefixes, RFC 8017 section 9.2 note 1 (SHA-3 OIDs
         * 2.16.840.1.101.3.4.2.7-10). */
        private static byte[] Prefix(FipsHashType h) => h switch {
            FipsHashType.Sha1 => Hex("3021300906052b0e03021a05000414"),
            FipsHashType.Sha224 => Hex("302d300d06096086480165030402040500041c"),
            FipsHashType.Sha256 => Hex("3031300d060960864801650304020105000420"),
            FipsHashType.Sha384 => Hex("3041300d060960864801650304020205000430"),
            FipsHashType.Sha512 => Hex("3051300d060960864801650304020305000440"),
            FipsHashType.Sha3_224 => Hex("302d300d06096086480165030402070500041c"),
            FipsHashType.Sha3_256 => Hex("3031300d060960864801650304020805000420"),
            FipsHashType.Sha3_384 => Hex("3041300d060960864801650304020905000430"),
            FipsHashType.Sha3_512 => Hex("3051300d060960864801650304020a05000440"),
            _ => throw new ArgumentOutOfRangeException(nameof(h))
        };

        internal static byte[] DigestInfo(FipsHashType hash, byte[] digest)
        {
            CheckDigest(hash, digest);
            return Prefix(hash).Concat(digest).ToArray();
        }

        private static byte[] Hex(string s) => Convert.FromHexString(s);

        protected override void FreeNative()
        {
            if (initialized)
                Native.wc_FreeRsaKey_fips(Handle);
        }
    }
}
