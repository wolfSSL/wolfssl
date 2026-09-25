/* FipsEcc.cs
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
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;

namespace wolfSSL.CSharp.Fips
{
    /* NIST prime curves; values are the module's ecc_curve_id values. */
    public enum FipsEccCurve
    {
        /* P-192: public key import and signature verification only
         * (FIPS 186-5 disallows P-192 key generation and signing). */
        P192 = 1,
        P224 = 14,
        P256 = 7,
        P384 = 15,
        P521 = 16
    }

    /* FIPS module ECC key: key generation, ECDSA sign/verify and ECC CDH (SP 800-56A).
     * Keys come from Generate, or ImportPublic for a peer's public key (04 || X || Y);
     * the v5.2.1 boundary has no ECC private key import. */
    public sealed class FipsEccKey : FipsObject
    {
        /* Key-owned DRBG: the native ecc_key keeps a pointer to it, so it is never exposed
         * to the caller and is freed only after wc_ecc_free_fips. A key is not thread-safe. */
        private FipsRng? ownRng;

        public FipsEccCurve Curve { get; }
        public bool HasPrivateKey { get; }
        public int FieldSize => FieldSizeOf(Curve);

        private FipsEccKey(FipsEccCurve curve, bool priv) : base(FipsStructType.Ecc)
        {
            Curve = curve;
            HasPrivateKey = priv;
            int ret = Native.wc_ecc_init_fips(Handle);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_ecc_init_fips", ret);
            }
            SetNativeFree(p => Native.wc_ecc_free_fips(p));
        }

        /* Generates a key pair (with the module's pairwise consistency test). The key then
         * binds its own DRBG for signing and CDH blinding, so rng may be disposed afterwards. */
        public static FipsEccKey Generate(FipsEccCurve curve, FipsRng rng)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            if (curve == FipsEccCurve.P192)
                throw new ArgumentException("P-192 key generation is not approved", nameof(curve));
            var k = new FipsEccKey(curve, true);
            try {
                using (rng.Use())
                    WolfCryptFipsException.Check("wc_ecc_make_key_ex_fips",
                        Native.wc_ecc_make_key_ex_fips(rng.Handle, FieldSizeOf(curve), k.Handle, (int)curve));
                var own = new FipsRng();
                k.ownRng = own;
                k.SetNativeFree(p => {
                    int ret = Native.wc_ecc_free_fips(p);
                    own.Dispose();
                    return ret;
                });
                WolfCryptFipsException.Check("wc_ecc_set_rng_fips", Native.wc_ecc_set_rng_fips(k.Handle, own.Handle));
            }
            catch {
                k.Dispose();
                throw;
            }
            return k;
        }

        /* Imports a public key (04 || X || Y), fully validated per SP 800-56A 5.6.2.3.3: by
         * the module on import if built with WOLFSSL_VALIDATE_ECC_IMPORT, else by Check here,
         * so an unvalidated point never reaches verification or CDH. */
        public static FipsEccKey ImportPublic(FipsEccCurve curve, byte[] x963)
        {
            if (x963 == null)
                throw new ArgumentNullException(nameof(x963));
            if (x963.Length != 1 + 2 * FieldSizeOf(curve) || x963[0] != 0x04)
                throw new ArgumentException("expected an uncompressed " + curve + " point", nameof(x963));
            var k = new FipsEccKey(curve, false);
            try {
                WolfCryptFipsException.Check("wc_ecc_import_x963_fips",
                    Native.wc_ecc_import_x963_fips(x963, (uint)x963.Length, k.Handle));
                if (Native.SizeOf((int)FipsStructType.ValidateEccImport) != 1)
                    k.Check();
            }
            catch {
                k.Dispose();
                throw;
            }
            return k;
        }

        /* Full public key validation (wc_ecc_check_key_fips). Throws if
         * the key is invalid. */
        public void Check()
        {
            ThrowIfDisposed();
            WolfCryptFipsException.Check("wc_ecc_check_key_fips", Native.wc_ecc_check_key_fips(Handle));
        }

        /* Public key as 04 || X || Y. */
        public byte[] ExportPublic()
        {
            ThrowIfDisposed();
            byte[] buf = new byte[1 + 2 * FieldSize];
            uint len = (uint)buf.Length;
            /* the module gates x963 export behind the private key read enable */
            WolfCryptFipsException.Check("wc_ecc_export_x963_fips",
                FipsModule.WithPrivateKeyRead(() => Native.wc_ecc_export_x963_fips(Handle, buf, ref len)));
            return buf.Take((int)len).ToArray();
        }

        /* ECDSA signature over a digest made with hash, as DER SEQUENCE { r, s }.
         * SHA-1 is refused for signing (SP 800-131A); the digest length must match hash. */
        public byte[] SignHash(FipsHashType hash, byte[] digest)
        {
            if (digest == null)
                throw new ArgumentNullException(nameof(digest));
            FipsRsaKey.RejectSha1ForSigning(hash);
            if (digest.Length != FipsHash.DigestSizeOf(hash))
                throw new ArgumentException("digest length does not match " + hash, nameof(digest));
            RequirePrivate();
            if (Curve == FipsEccCurve.P192)
                throw new InvalidOperationException("P-192 signing is not approved");
            byte[] sig = new byte[9 + 2 * (FieldSize + 1)];   /* max DER SEQUENCE { r, s } */
            uint len = (uint)sig.Length;
            using (ownRng!.Use())
                WolfCryptFipsException.Check("wc_ecc_sign_hash_fips",
                    Native.wc_ecc_sign_hash_fips(digest, (uint)digest.Length, sig, ref len, ownRng.Handle, Handle));
            return sig.Take((int)len).ToArray();
        }

        /* Verifies a DER signature. The digest length must match hash (FIPS 186-5 6.4.2): the
         * v5.2.x module has no bound, and a very short digest makes signatures forgeable
         * (CVE-2026-5194). SHA-1 is accepted for legacy verification. */
        public bool VerifyHash(FipsHashType hash, byte[] digest, byte[] derSignature)
        {
            if (digest == null || derSignature == null)
                throw new ArgumentNullException(digest == null ? nameof(digest) : nameof(derSignature));
            if (digest.Length != FipsHash.DigestSizeOf(hash))
                throw new ArgumentException("digest length does not match " + hash, nameof(digest));
            ThrowIfDisposed();
            int ret = Native.wc_ecc_verify_hash_fips(derSignature, (uint)derSignature.Length,
                                                     digest, (uint)digest.Length, out int res, Handle);
            if (FipsError.IsModuleStateError(ret))
                throw new WolfCryptFipsException("wc_ecc_verify_hash_fips", ret);
            return ret == 0 && res == 1;
        }

        /* ECC CDH (KAS-ECC-SSC): shared secret Z (x-coordinate, FieldSize bytes) with a peer's
         * public key on the same curve. Approved on P-256, P-384 and P-521 only (validated
         * domains, SP #4718); P-192 and P-224 are refused. */
        public byte[] SharedSecret(FipsEccKey peerPublic)
        {
            if (peerPublic == null)
                throw new ArgumentNullException(nameof(peerPublic));
            if (Curve == FipsEccCurve.P192 || Curve == FipsEccCurve.P224)
                throw new InvalidOperationException("ECC CDH is approved on P-256, P-384 and P-521 only");
            RequirePrivate();
            peerPublic.ThrowIfDisposed();
            if (peerPublic.Curve != Curve)
                throw new ArgumentException("curve mismatch", nameof(peerPublic));
            byte[] z = GC.AllocateArray<byte>(FieldSize, pinned: true);
            uint len = (uint)z.Length;
            try {
                using (ownRng!.Use())
                    WolfCryptFipsException.Check("wc_ecc_shared_secret_fips", FipsModule.WithPrivateKeyRead(() =>
                        Native.wc_ecc_shared_secret_fips(Handle, peerPublic.Handle, z, ref len)));
                return z.Take((int)len).ToArray();
            }
            finally {
                CryptographicOperations.ZeroMemory(z);
            }
        }

        public static int FieldSizeOf(FipsEccCurve c) => c switch {
            FipsEccCurve.P192 => 24,
            FipsEccCurve.P224 => 28,
            FipsEccCurve.P256 => 32,
            FipsEccCurve.P384 => 48,
            FipsEccCurve.P521 => 66,
            _ => throw new ArgumentOutOfRangeException(nameof(c))
        };

        private void RequirePrivate()
        {
            ThrowIfDisposed();
            if (!HasPrivateKey)
                throw new InvalidOperationException("operation requires a private key");
        }
    }
}
