/* Pkcs1.cs
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
using System.Security.Cryptography;

namespace wolfSSL.CSharp.Fips.Test
{
    /* PKCS#1 v1.5 caller side for the tests: DigestInfo encoding (what an
     * application does with wc_EncodeSignature, outside the module) and
     * verification by comparing the block the module recovers. Built with
     * AsnWriter from the dotted OIDs, independently of the wrapper. */
    internal static class Pkcs1
    {
        internal static string Oid(FipsHashType h) => h switch
        {
            FipsHashType.Sha1 => "1.3.14.3.2.26",
            FipsHashType.Sha224 => "2.16.840.1.101.3.4.2.4",
            FipsHashType.Sha256 => "2.16.840.1.101.3.4.2.1",
            FipsHashType.Sha384 => "2.16.840.1.101.3.4.2.2",
            FipsHashType.Sha512 => "2.16.840.1.101.3.4.2.3",
            FipsHashType.Sha3_224 => "2.16.840.1.101.3.4.2.7",
            FipsHashType.Sha3_256 => "2.16.840.1.101.3.4.2.8",
            FipsHashType.Sha3_384 => "2.16.840.1.101.3.4.2.9",
            _ => "2.16.840.1.101.3.4.2.10"
        };

        internal static byte[] DigestInfo(FipsHashType h, byte[] digest)
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence())
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier(Oid(h));
                    w.WriteNull();
                }
                w.WriteOctetString(digest);
            }
            return w.Encode();
        }

        internal static byte[] Sign(FipsRsaKey key, FipsHashType h, byte[] digest, FipsRng rng) =>
            key.SignPkcs1v15(DigestInfo(h, digest), rng);

        internal static bool Verify(FipsRsaKey key, FipsHashType h, byte[] digest, byte[] signature)
        {
            byte[]? recovered = key.RecoverPkcs1v15(signature);
            return recovered != null && CryptographicOperations.FixedTimeEquals(recovered, DigestInfo(h, digest));
        }
    }
}
