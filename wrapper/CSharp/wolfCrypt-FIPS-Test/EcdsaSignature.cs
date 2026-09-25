/* EcdsaSignature.cs
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

namespace wolfSSL.CSharp.Fips.Test
{
    /* ECC test helpers outside the boundary API: public key import from
     * separate X and Y (the boundary imports 04 || X || Y only). */
    internal static class EccTestHelpers
    {
        internal static FipsEccKey ImportPublic(FipsEccCurve curve, byte[] x, byte[] y)
        {
            if (x == null || y == null)
            {
                throw new ArgumentNullException(x == null ? nameof(x) : nameof(y));
            }

            int n = FipsEccKey.FieldSizeOf(curve);
            return FipsEccKey.ImportPublic(curve, new byte[] { 0x04 }.Concat(LeftPad(x, n)).Concat(LeftPad(y, n)).ToArray());
        }

        internal static byte[] LeftPad(byte[] v, int n)
        {
            if (v.Length > n)
            {
                int skip = v.Length - n;
                if (v.Take(skip).Any(b => b != 0))
                {
                    throw new ArgumentException("value too large for curve");
                }

                return v.Skip(skip).ToArray();
            }
            return new byte[n - v.Length].Concat(v).ToArray();
        }
    }

    /* ECDSA signature encoding helpers for the tests (ACVP r/s vectors,
     * .NET P1363 signatures): DER SEQUENCE { INTEGER r, INTEGER s } and
     * fixed-width r || s. Not part of the wrapper: the boundary has no
     * r/s conversion. */
    internal static class FipsEcdsaSignature
    {
        public static byte[] ToDer(byte[] r, byte[] s)
        {
            if (r == null || s == null)
            {
                throw new ArgumentNullException(r == null ? nameof(r) : nameof(s));
            }

            byte[] ri = DerInteger(r), si = DerInteger(s);
            return new byte[] { 0x30 }.Concat(DerLength(ri.Length + si.Length)).Concat(ri).Concat(si).ToArray();
        }

        /* Fixed-width r || s, each fieldSize bytes. */
        public static byte[] ToP1363(byte[] der, int fieldSize)
        {
            var (r, s) = FromDer(der);
            return EccTestHelpers.LeftPad(r, fieldSize).Concat(EccTestHelpers.LeftPad(s, fieldSize)).ToArray();
        }

        public static byte[] FromP1363(byte[] rs)
        {
            if (rs == null)
            {
                throw new ArgumentNullException(nameof(rs));
            }

            if (rs.Length % 2 != 0)
            {
                throw new ArgumentException("r || s must have even length", nameof(rs));
            }

            int n = rs.Length / 2;
            return ToDer(rs.Take(n).ToArray(), rs.Skip(n).ToArray());
        }

        /* Strict DER decode of SEQUENCE { INTEGER r, INTEGER s }: rejects
         * truncated or trailing data, non-minimal lengths and integers, and
         * non-positive values. Throws FormatException on any violation. */
        public static (byte[] r, byte[] s) FromDer(byte[] der)
        {
            if (der == null)
            {
                throw new ArgumentNullException(nameof(der));
            }

            try
            {
                var outer = new AsnReader(der, AsnEncodingRules.DER);
                AsnReader seq = outer.ReadSequence();
                outer.ThrowIfNotEmpty();
                byte[] r = ReadPositive(seq);
                byte[] s = ReadPositive(seq);
                seq.ThrowIfNotEmpty();
                return (r, s);
            }
            catch (AsnContentException e)
            {
                throw new FormatException("invalid DER ECDSA signature", e);
            }
        }

        private static byte[] DerInteger(byte[] v)
        {
            byte[] t = v.SkipWhile(b => b == 0).ToArray();
            if (t.Length == 0)
            {
                t = new byte[] { 0 };
            }

            if ((t[0] & 0x80) != 0)
            {
                t = new byte[] { 0 }.Concat(t).ToArray();
            }

            return new byte[] { 0x02 }.Concat(DerLength(t.Length)).Concat(t).ToArray();
        }

        private static byte[] DerLength(int len) =>
            len < 0x80 ? new[] { (byte)len } : len <= 0xff ? new byte[] { 0x81, (byte)len }
                                                            : new byte[] { 0x82, (byte)(len >> 8), (byte)len };

        private static byte[] ReadPositive(AsnReader seq)
        {
            ReadOnlyMemory<byte> v = seq.ReadIntegerBytes();
            ReadOnlySpan<byte> b = v.Span;
            if ((b[0] & 0x80) != 0)
            {
                throw new FormatException("negative INTEGER in ECDSA signature");
            }

            if (b.Length == 1 && b[0] == 0)
            {
                throw new FormatException("zero INTEGER in ECDSA signature");
            }

            return (b[0] == 0 ? b.Slice(1) : b).ToArray();
        }
    }
}
