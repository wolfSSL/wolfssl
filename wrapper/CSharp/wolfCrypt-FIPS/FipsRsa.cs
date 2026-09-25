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

    /* RSA key pair generated in the FIPS module; the v5.2.1 boundary has no RSA key import.
     * Export returns all components and is gated by the private key read enable. */
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
            try {
                using (rng.Use())
                    ret = Native.wc_MakeRsaKey_fips(Handle, bits, new CLong(checked((nint)exponent)), rng.Handle);
            }
            catch {
                Dispose();
                throw;
            }
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
            /* No public-only export in the module: capture n and e once here, so private
             * components cross the boundary once per key, not on every ExportPublic. */
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

        /* Serializes module calls on this key: a concurrent call would free the per-key
         * buffer (RsaKey.data) under another. Taken before a FipsRng lease, never after. */
        private readonly object sync = new object();

        /* Modulus sizes approved for key generation (FIPS 186-5,
         * SP 800-131A Rev. 2; cert #4718 Security Policy Table 7). */
        private static readonly int[] approvedKeySizes = { 2048, 3072, 4096 };
        public static System.Collections.Generic.IReadOnlyList<int> ApprovedKeySizes { get; } =
            Array.AsReadOnly(approvedKeySizes);

        /* FIPS 186 key generation, including the module's pairwise consistency test. The
         * size is checked here: the v5.2.1 module also accepts 1024 (bug 6367), which is
         * disallowed. */
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
            /* the module takes a C long (32 bits on Windows and 32-bit platforms);
             * refuse values it cannot represent rather than truncate them */
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
            lock (sync)
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
                lock (sync)
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

        /* Signs a caller-built DER DigestInfo (RFC 8017 9.2); its encoding is outside the
         * boundary, as in CAVP testing. Only a canonical SHA-2 DigestInfo is accepted: SHA-1 is
         * disallowed for signing (SP 800-131A) and RSA SigGen is not validated with SHA-3. */
        public byte[] SignPkcs1v15(byte[] digestInfo, FipsRng rng)
        {
            if (digestInfo == null)
                throw new ArgumentNullException(nameof(digestInfo));
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            FipsHashType hash = HashOfDigestInfo(digestInfo);
            RejectSha1ForSigning(hash);
            if (hash >= FipsHashType.Sha3_224)
                throw new ArgumentException("SHA-3 is not in the validated RSA PKCS#1 v1.5 signature generation",
                                            nameof(digestInfo));
            byte[] sig = new byte[Size];
            ThrowIfDisposed();
            int ret;
            lock (sync)
                using (rng.Use())
                    ret = Native.wc_RsaSSL_Sign_fips(digestInfo, (uint)digestInfo.Length, sig, (uint)sig.Length,
                                                     Handle, rng.Handle);
            if (ret < 0)
                throw new WolfCryptFipsException("wc_RsaSSL_Sign_fips", ret);
            return sig.Take(ret).ToArray();
        }

        /* RSA public operation and PKCS#1 v1.5 unpadding: the recovered block, or null if it
         * does not unpad. The caller compares it in constant time (FixedTimeEquals) with the
         * expected DigestInfo, as the module's CAVP testing did. */
        public byte[]? RecoverPkcs1v15(byte[] signature)
        {
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            byte[] recovered = new byte[Size];
            ThrowIfDisposed();
            int ret;
            lock (sync)
                ret = Native.wc_RsaSSL_Verify_fips(signature, (uint)signature.Length, recovered,
                                                   (uint)recovered.Length, Handle);
            if (ret < 0) {
                VerifyFailure("wc_RsaSSL_Verify_fips", ret);   /* throws on module-state errors */
                return null;
            }
            return recovered.Take(ret).ToArray();
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
            ThrowIfDisposed();
            int ret;
            lock (sync)
                using (rng.Use())
                    ret = Native.wc_RsaPSS_SignEx_fips(digest, (uint)digest.Length, sig, (uint)sig.Length,
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
            int ret;
            lock (sync)
                ret = Native.wc_RsaPSS_VerifyEx_fips((byte[])signature.Clone(), (uint)signature.Length,
                    decoded, (uint)decoded.Length, (int)hash, Mgf(hash), saltLen, Handle);
            if (ret < 0)
                return VerifyFailure("wc_RsaPSS_VerifyEx_fips", ret);
            ret = Native.wc_RsaPSS_CheckPaddingEx_fips(digest, (uint)digest.Length, decoded, (uint)ret,
                (int)hash, saltLen, Bits);
            if (FipsError.IsModuleStateError(ret))
                throw new WolfCryptFipsException("wc_RsaPSS_CheckPaddingEx_fips", ret);
            return ret == 0;
        }

        /* ---- RSA encryption primitives (RSAEP/RSADP) with OAEP padding ----
         * No SP 800-56B KTS claim in the Security Policy: not an approved key-transport service.
         * Encrypt targets only this key (no key import); PKCS#1 v1.5 and raw RSA not offered. */

        private const int WC_RSA_OAEP_PAD = 1;

        public byte[] Encrypt(byte[] plaintext, FipsRng rng,
                              FipsHashType oaepHash = FipsHashType.Sha256, byte[]? label = null)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            ThrowIfDisposed();
            byte[] ct = new byte[Size];
            int ret;
            lock (sync)
                using (rng.Use())
                    ret = Native.wc_RsaPublicEncryptEx_fips(plaintext, (uint)plaintext.Length, ct, (uint)ct.Length,
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
            int ret;
            lock (sync)
                ret = Native.wc_RsaPrivateDecryptEx_fips(ciphertext, (uint)ciphertext.Length, pt, (uint)pt.Length,
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

        /* FIPS 186-5 5.4(g): 0 <= sLen <= hLen, enforced here because WOLFSSL_PSS_LONG_SALT
         * (configure adds it with TLS 1.3) removes the module's own check. -1 selects
         * sLen = hLen; salt discovery (-2) is not offered because it accepts any length. */
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

        /* Canonical DER DigestInfo prefixes (RFC 8017 9.2 note 1), used only to recognize
         * the caller's DigestInfo, never to build one. */
        private static readonly (FipsHashType Hash, byte[] Prefix)[] Prefixes = {
            (FipsHashType.Sha1, Hex("3021300906052b0e03021a05000414")),
            (FipsHashType.Sha224, Hex("302d300d06096086480165030402040500041c")),
            (FipsHashType.Sha256, Hex("3031300d060960864801650304020105000420")),
            (FipsHashType.Sha384, Hex("3041300d060960864801650304020205000430")),
            (FipsHashType.Sha512, Hex("3051300d060960864801650304020305000440")),
            (FipsHashType.Sha3_224, Hex("302d300d06096086480165030402070500041c")),
            (FipsHashType.Sha3_256, Hex("3031300d060960864801650304020805000420")),
            (FipsHashType.Sha3_384, Hex("3041300d060960864801650304020905000430")),
            (FipsHashType.Sha3_512, Hex("3051300d060960864801650304020a05000440")),
        };

        /* Hash of a DigestInfo that is exactly prefix || digest of the right
         * length for a known hash; ArgumentException otherwise. */
        private static FipsHashType HashOfDigestInfo(byte[] di)
        {
            foreach (var (hash, prefix) in Prefixes)
                if (di.Length == prefix.Length + FipsHash.DigestSizeOf(hash) && di.AsSpan().StartsWith(prefix))
                    return hash;
            throw new ArgumentException("not the DER DigestInfo of a supported hash digest (RFC 8017 9.2)",
                                        "digestInfo");
        }

        private static byte[] Hex(string s) => Convert.FromHexString(s);
    }
}
