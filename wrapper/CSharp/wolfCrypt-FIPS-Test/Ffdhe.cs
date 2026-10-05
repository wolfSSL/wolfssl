/* Ffdhe.cs
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

using System.Collections.Generic;

namespace wolfSSL.CSharp.Fips.Test
{
    /* RFC 7919 appendix A ffdhe2048 safe prime (g = 2), used as an independent
     * reference for DH agreement and public key computation. Copied from
     * the RFC text and checked when added: bit length, all-ones top and
     * bottom 64 bits, Fermat test. */
    internal static class Ffdhe
    {
        /* module ids of the groups outside the validated KAS-FFC-SSC */
        internal const FipsDhGroup Ffdhe3072 = (FipsDhGroup)257;
        internal const FipsDhGroup Ffdhe4096 = (FipsDhGroup)258;
        internal const FipsDhGroup Ffdhe6144 = (FipsDhGroup)259;
        internal const FipsDhGroup Ffdhe8192 = (FipsDhGroup)260;

        public static readonly Dictionary<FipsDhGroup, byte[]> P = new()
        {
            [FipsDhGroup.Ffdhe2048] = T.Hex(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
                "c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff")
        };
    }
}
