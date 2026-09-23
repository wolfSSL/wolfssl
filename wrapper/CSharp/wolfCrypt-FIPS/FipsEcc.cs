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

    /* ECC key from the FIPS module: key generation, ECDSA sign/verify and
     * ECC CDH shared secret (SP 800-56A).
     *
     * Keys come from Generate, or ImportPublic for a peer's public key
     * (X9.63 uncompressed point, 04 || X || Y). The v5.2.3 boundary has no
     * ECC private key import. */
    public sealed class FipsEccKey : FipsObject
    {
        private bool initialized;
        private FipsRng? rng;   /* referenced by the native key; kept alive */

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
            initialized = true;
        }

        /* Generates a key pair (includes the module's pairwise consistency
         * test). rng is kept by the key for signing and CDH blinding. */
        public static FipsEccKey Generate(FipsEccCurve curve, FipsRng rng)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            if (curve == FipsEccCurve.P192)
                throw new ArgumentException("P-192 key generation is not approved", nameof(curve));
            rng.ThrowIfDisposed();
            var k = new FipsEccKey(curve, true);
            try {
                WolfCryptFipsException.Check("wc_ecc_make_key_ex_fips",
                    Native.wc_ecc_make_key_ex_fips(rng.Handle, FieldSizeOf(curve), k.Handle, (int)curve));
                WolfCryptFipsException.Check("wc_ecc_set_rng_fips", Native.wc_ecc_set_rng_fips(k.Handle, rng.Handle));
                k.rng = rng;
            }
            catch {
                k.Dispose();
                throw;
            }
            return k;
        }

        /* Imports a public key (04 || X || Y). The curve is determined by
         * the point size and must match curve. */
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
            }
            catch {
                k.Dispose();
                throw;
            }
            return k;
        }

        public static FipsEccKey ImportPublic(FipsEccCurve curve, byte[] x, byte[] y)
        {
            int n = FieldSizeOf(curve);
            return ImportPublic(curve, new byte[] { 0x04 }.Concat(LeftPad(x, n)).Concat(LeftPad(y, n)).ToArray());
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

        /* ECDSA signature over a message digest made with hash; returns DER
         * SEQUENCE { r, s } (see FipsEcdsaSignature for r/s conversion).
         * SHA-1 is refused (signature generation, SP 800-131A); the digest
         * length must match hash. */
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
            byte[] sig = new byte[FipsEcdsaSignature.MaxDerSize(FieldSize)];
            uint len = (uint)sig.Length;
            WolfCryptFipsException.Check("wc_ecc_sign_hash_fips",
                Native.wc_ecc_sign_hash_fips(digest, (uint)digest.Length, sig, ref len, rng!.Handle, Handle));
            return sig.Take((int)len).ToArray();
        }

        /* Verifies a DER signature over a digest. */
        public bool VerifyHash(byte[] digest, byte[] derSignature)
        {
            if (digest == null || derSignature == null)
                throw new ArgumentNullException(digest == null ? nameof(digest) : nameof(derSignature));
            ThrowIfDisposed();
            int ret = Native.wc_ecc_verify_hash_fips(derSignature, (uint)derSignature.Length,
                                                     digest, (uint)digest.Length, out int res, Handle);
            if (FipsError.IsModuleStateError(ret))
                throw new WolfCryptFipsException("wc_ecc_verify_hash_fips", ret);
            return ret == 0 && res == 1;
        }

        /* ECC CDH primitive: shared secret Z (x-coordinate, FieldSize
         * bytes) with a peer's public key on the same curve. */
        public byte[] SharedSecret(FipsEccKey peerPublic)
        {
            if (peerPublic == null)
                throw new ArgumentNullException(nameof(peerPublic));
            RequirePrivate();
            peerPublic.ThrowIfDisposed();
            if (peerPublic.Curve != Curve)
                throw new ArgumentException("curve mismatch", nameof(peerPublic));
            byte[] z = new byte[FieldSize];
            uint len = (uint)z.Length;
            WolfCryptFipsException.Check("wc_ecc_shared_secret_fips", FipsModule.WithPrivateKeyRead(() =>
                Native.wc_ecc_shared_secret_fips(Handle, peerPublic.Handle, z, ref len)));
            return z.Take((int)len).ToArray();
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

        internal static byte[] LeftPad(byte[] v, int n)
        {
            if (v.Length > n) {
                int skip = v.Length - n;
                if (v.Take(skip).Any(b => b != 0))
                    throw new ArgumentException("value too large for curve");
                return v.Skip(skip).ToArray();
            }
            return new byte[n - v.Length].Concat(v).ToArray();
        }

        protected override void FreeNative()
        {
            if (initialized)
                Native.wc_ecc_free_fips(Handle);
        }
    }

    /* ECDSA signature encoding helpers: DER SEQUENCE { INTEGER r,
     * INTEGER s } and fixed-width r || s (IEEE P1363). Formatting only. */
    public static class FipsEcdsaSignature
    {
        internal static int MaxDerSize(int fieldSize) => 9 + 2 * (fieldSize + 1);

        public static byte[] ToDer(byte[] r, byte[] s)
        {
            byte[] ri = DerInteger(r), si = DerInteger(s);
            return new byte[] { 0x30 }.Concat(DerLength(ri.Length + si.Length)).Concat(ri).Concat(si).ToArray();
        }

        /* Fixed-width r || s, each fieldSize bytes. */
        public static byte[] ToP1363(byte[] der, int fieldSize)
        {
            var (r, s) = FromDer(der);
            return FipsEccKey.LeftPad(r, fieldSize).Concat(FipsEccKey.LeftPad(s, fieldSize)).ToArray();
        }

        public static byte[] FromP1363(byte[] rs)
        {
            if (rs == null || rs.Length % 2 != 0)
                throw new ArgumentException("r || s must have even length", nameof(rs));
            int n = rs.Length / 2;
            return ToDer(rs.Take(n).ToArray(), rs.Skip(n).ToArray());
        }

        public static (byte[] r, byte[] s) FromDer(byte[] der)
        {
            int i = 0;
            if (der[i++] != 0x30) throw new FormatException("not a SEQUENCE");
            ReadLength(der, ref i);
            byte[] r = ReadInteger(der, ref i);
            byte[] s = ReadInteger(der, ref i);
            return (r, s);
        }

        private static byte[] DerInteger(byte[] v)
        {
            byte[] t = v.SkipWhile(b => b == 0).ToArray();
            if (t.Length == 0) t = new byte[] { 0 };
            if ((t[0] & 0x80) != 0) t = new byte[] { 0 }.Concat(t).ToArray();
            return new byte[] { 0x02 }.Concat(DerLength(t.Length)).Concat(t).ToArray();
        }

        private static byte[] DerLength(int len) =>
            len < 0x80 ? new[] { (byte)len } : len <= 0xff ? new byte[] { 0x81, (byte)len }
                                                            : new byte[] { 0x82, (byte)(len >> 8), (byte)len };

        private static int ReadLength(byte[] d, ref int i)
        {
            int b = d[i++];
            if (b < 0x80) return b;
            int n = b & 0x7f, len = 0;
            for (int k = 0; k < n; k++) len = (len << 8) | d[i++];
            return len;
        }

        private static byte[] ReadInteger(byte[] d, ref int i)
        {
            if (d[i++] != 0x02) throw new FormatException("not an INTEGER");
            int len = ReadLength(d, ref i);
            byte[] v = d.Skip(i).Take(len).ToArray();
            i += len;
            return v.SkipWhile(b => b == 0).ToArray();
        }
    }
}
