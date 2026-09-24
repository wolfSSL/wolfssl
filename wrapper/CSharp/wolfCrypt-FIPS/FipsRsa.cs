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
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace wolfSSL.CSharp.Fips
{
    /* Public RSA key components (big-endian). */
    public sealed class FipsRsaPublicKey
    {
        public byte[] Modulus { get; }
        public byte[] Exponent { get; }
        internal FipsRsaPublicKey(byte[] n, byte[] e) { Modulus = n; Exponent = e; }
    }

    /* Full RSA key components (big-endian). Dispose zeroes D, P and Q. */
    public sealed class FipsRsaKeyComponents : IDisposable
    {
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(D);
            CryptographicOperations.ZeroMemory(P);
            CryptographicOperations.ZeroMemory(Q);
        }

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

        /* Modulus size in bytes (signature / ciphertext size). */
        public int Size { get; }
        public int Bits => Size * 8;

        private FipsRsaKey(int bits, long exponent, FipsRng rng) : base(FipsStructType.Rsa)
        {
            if (rng == null || rng.Handle.IsClosed) {
                Dispose();
                if (rng == null)
                    throw new ArgumentNullException(nameof(rng));
                throw new ObjectDisposedException(nameof(FipsRng));
            }
            int ret = Native.wc_InitRsaKey_fips(Handle, IntPtr.Zero);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_InitRsaKey_fips", ret);
            }
            SetNativeFree(p => Native.wc_FreeRsaKey_fips(p));
            ret = Native.wc_MakeRsaKey_fips(Handle, bits, new CLong(checked((nint)exponent)), rng.Handle);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_MakeRsaKey_fips", ret);
            }
            Size = Native.wc_RsaEncryptSize_fips(Handle);
            if (Size <= 0) {
                /* gated like every RSA service: a module-state error here */
                int err = Size;
                Dispose();
                throw new WolfCryptFipsException("wc_RsaEncryptSize_fips", err);
            }
            /* The module has no public-only export: capture n and e once,
             * here, so the private components cross the boundary once per
             * key rather than on every ExportPublic. */
            try {
                using FipsRsaKeyComponents c = FipsModule.WithPrivateKeyRead(() => Export());
                publicKey = new FipsRsaPublicKey((byte[])c.N.Clone(), (byte[])c.E.Clone());
            }
            catch {
                Dispose();
                throw;
            }
        }

        private readonly FipsRsaPublicKey publicKey;

        /* Modulus sizes approved for key generation (FIPS 186-5,
         * SP 800-131A Rev. 2; cert #4718 Security Policy Table 7). */
        private static readonly int[] approvedKeySizes = { 2048, 3072, 4096 };
        public static System.Collections.Generic.IReadOnlyList<int> ApprovedKeySizes { get; } =
            Array.AsReadOnly(approvedKeySizes);

        /* Generates a key pair (FIPS 186 key generation, includes the
         * module's pairwise consistency test).
         *
         * The size is checked here: the v5.2.1 and v5.2.3 modules also
         * accept 1024 (bug 6367, RsaSizeCheck), which is disallowed. */
        public static FipsRsaKey Generate(int bits, FipsRng rng, long exponent = DefaultExponent)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            if (Array.IndexOf(approvedKeySizes, bits) < 0)
                throw new ArgumentException("RSA key size must be 2048, 3072 or 4096 bits", nameof(bits));
            /* FIPS 186-5 5.4(e): e odd, 2^16 < e < 2^256 (the module also
             * accepts e = 3). */
            if (exponent <= 65536 || (exponent & 1) == 0)
                throw new ArgumentOutOfRangeException(nameof(exponent), "exponent must be odd and greater than 2^16");
            /* the module takes a C long (32 bits on Windows and 32-bit
             * platforms); refuse values it cannot represent rather than let
             * them be truncated */
            bool cLongIs32 = IntPtr.Size == 4 || OperatingSystem.IsWindows();
            if (cLongIs32 && exponent > int.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(exponent), "exponent does not fit the platform's C long");
            /* FIPS 186 prime generation stops after a bounded number of
             * candidates and reports failure (PRIME_GEN_E); that is rare and
             * the standard allows trying again with fresh random input. */
            const int attempts = 3;
            for (int i = 1; ; i++) {
                try {
                    return new FipsRsaKey(bits, exponent, rng);
                }
                catch (WolfCryptFipsException e) when (e.Code == FipsError.PRIME_GEN_E && i < attempts) {
                }
            }
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
            /* private temporaries are pinned so the GC cannot leave moved,
             * unzeroed copies behind */
            byte[] e = new byte[8], n = new byte[Size], d = GC.AllocateArray<byte>(Size, pinned: true),
                   p = GC.AllocateArray<byte>(Size, pinned: true), q = GC.AllocateArray<byte>(Size, pinned: true);
            uint eSz = (uint)e.Length, nSz = (uint)n.Length, dSz = (uint)d.Length,
                 pSz = (uint)p.Length, qSz = (uint)q.Length;
            try {
                WolfCryptFipsException.Check("wc_RsaExportKey_fips",
                    Native.wc_RsaExportKey_fips(Handle, e, ref eSz, n, ref nSz, d, ref dSz, p, ref pSz, q, ref qSz));
                return new FipsRsaKeyComponents(e.Take((int)eSz).ToArray(), n.Take((int)nSz).ToArray(),
                    PinnedCopy(d, dSz), PinnedCopy(p, pSz), PinnedCopy(q, qSz));
            }
            finally {
                CryptographicOperations.ZeroMemory(d);
                CryptographicOperations.ZeroMemory(p);
                CryptographicOperations.ZeroMemory(q);
            }
        }

        /* Public components (captured when the key was generated). */
        public FipsRsaPublicKey ExportPublic()
        {
            ThrowIfDisposed();
            return new FipsRsaPublicKey((byte[])publicKey.Modulus.Clone(), (byte[])publicKey.Exponent.Clone());
        }

        /* ---- PKCS#1 v1.5 signatures (RSASSA-PKCS1-v1_5) ---- */

        /* Signs a message digest. digest must be the hash of the message
         * with the given algorithm; the DigestInfo encoding is added here.
         * SHA-1 is refused (signature generation, SP 800-131A). */
        public byte[] SignPkcs1v15(FipsHashType hash, byte[] digest, FipsRng rng)
        {
            RejectSha1ForSigning(hash);
            byte[] di = DigestInfo(hash, digest);
            byte[] sig = new byte[Size];
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
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
            RejectSha1ForSigning(hash);
            CheckDigest(hash, digest);
            CheckSaltLen(hash, saltLen);
            byte[] sig = new byte[Size];
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
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
            CheckSaltLen(hash, saltLen);
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

        /* ---- encryption: RSAES-OAEP (SP 800-56B) ----
         *
         * RSAES-PKCS1-v1_5 is not offered: SP 800-131A Rev. 2 disallows it
         * for key transport after 2023. */

        private const int WC_RSA_OAEP_PAD = 1;

        public byte[] Encrypt(byte[] plaintext, FipsRng rng,
                              FipsHashType oaepHash = FipsHashType.Sha256, byte[]? label = null)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            rng.ThrowIfDisposed();
            ThrowIfDisposed();
            byte[] ct = new byte[Size];
            int ret = Native.wc_RsaPublicEncryptEx_fips(plaintext, (uint)plaintext.Length, ct, (uint)ct.Length,
                Handle, rng.Handle, WC_RSA_OAEP_PAD, (int)oaepHash, Mgf(oaepHash),
                label, label == null ? 0u : (uint)label.Length);
            if (ret < 0)
                throw new WolfCryptFipsException("wc_RsaPublicEncryptEx_fips", ret);
            return ct.Take(ret).ToArray();
        }

        public byte[] Decrypt(byte[] ciphertext,
                              FipsHashType oaepHash = FipsHashType.Sha256, byte[]? label = null)
        {
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));
            ThrowIfDisposed();
            byte[] pt = GC.AllocateArray<byte>(Size, pinned: true);
            int ret = Native.wc_RsaPrivateDecryptEx_fips(ciphertext, (uint)ciphertext.Length, pt, (uint)pt.Length,
                Handle, WC_RSA_OAEP_PAD, (int)oaepHash, Mgf(oaepHash),
                label, label == null ? 0u : (uint)label.Length);
            try {
                if (ret < 0)
                    throw new WolfCryptFipsException("wc_RsaPrivateDecryptEx_fips", ret);
                return pt.Take(ret).ToArray();
            }
            finally {
                CryptographicOperations.ZeroMemory(pt);
            }
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

        private static byte[] PinnedCopy(byte[] src, uint len)
        {
            byte[] dst = GC.AllocateArray<byte>((int)len, pinned: true);
            Array.Copy(src, dst, (int)len);
            return dst;
        }

        /* SP 800-131A Rev. 2 section 9 and Security Policy rule 3b: SHA-1 is
         * disallowed for signature generation (verification stays allowed
         * for legacy signatures). */
        internal static void RejectSha1ForSigning(FipsHashType hash)
        {
            if (hash == FipsHashType.Sha1)
                throw new ArgumentException("SHA-1 is not allowed for signature generation", nameof(hash));
        }

        /* MGF1 identifiers from rsa.h */
        private static int Mgf(FipsHashType h) => h switch {
            FipsHashType.Sha1 => 26,
            FipsHashType.Sha224 => 4,
            FipsHashType.Sha256 => 1,
            FipsHashType.Sha384 => 2,
            FipsHashType.Sha512 => 3,
            _ => throw new NotSupportedException("MGF1 with " + h + " is not supported by this module")
        };

        /* FIPS 186-5 5.4(g): 0 <= sLen <= hLen. Builds with RSA-PSS define
         * WOLFSSL_PSS_LONG_SALT (configure adds it with TLS 1.3), which
         * removes the module's own sLen <= hLen check, so it is enforced
         * here for signing and verification. -1 selects sLen = hLen; salt
         * discovery (-2) is not offered because it accepts any length. */
        private static void CheckSaltLen(FipsHashType hash, int saltLen)
        {
            if (saltLen != -1 && (saltLen < 0 || saltLen > FipsHash.DigestSizeOf(hash)))
                throw new ArgumentOutOfRangeException(nameof(saltLen),
                    "PSS salt length must be -1 (digest length) or 0 to " + FipsHash.DigestSizeOf(hash) + " bytes");
        }

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
    }
}
