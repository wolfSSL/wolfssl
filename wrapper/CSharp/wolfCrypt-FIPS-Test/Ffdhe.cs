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
    /* RFC 7919 appendix A safe primes (g = 2), used as an independent
     * reference for DH agreement and public key computation. Copied from
     * the RFC text and checked when added: bit length, all-ones top and
     * bottom 64 bits, Fermat test. */
    internal static class Ffdhe
    {
        public static readonly Dictionary<FipsDhGroup, byte[]> P = new() {
            [FipsDhGroup.Ffdhe2048] = T.Hex(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
                "c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"),
            [FipsDhGroup.Ffdhe3072] = T.Hex(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b" +
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c" +
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff" +
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e" +
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff"),
            [FipsDhGroup.Ffdhe4096] = T.Hex(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b" +
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c" +
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff" +
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e" +
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb" +
                "7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a" +
                "7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038" +
                "092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf" +
                "8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e655f6affffffffffffffff"),
            [FipsDhGroup.Ffdhe6144] = T.Hex(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b" +
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c" +
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff" +
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e" +
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb" +
                "7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a" +
                "7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038" +
                "092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf" +
                "8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a" +
                "4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4c" +
                "b38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477" +
                "a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e" +
                "7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992" +
                "eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538c" +
                "d72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b9117" +
                "8ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e69" +
                "62a69526d43161c1a41d570d7938dad4a40e329cd0e40e65ffffffffffffffff"),
            [FipsDhGroup.Ffdhe8192] = T.Hex(
                "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
                "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
                "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
                "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
                "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
                "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
                "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
                "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b" +
                "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c" +
                "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff" +
                "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e" +
                "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb" +
                "7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a" +
                "7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038" +
                "092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf" +
                "8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a" +
                "4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4c" +
                "b38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477" +
                "a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e" +
                "7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992" +
                "eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538c" +
                "d72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b9117" +
                "8ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e69" +
                "62a69526d43161c1a41d570d7938dad4a40e329ccff46aaa36ad004cf600c838" +
                "1e425a31d951ae64fdb23fcec9509d43687feb69edd1cc5e0b8cc3bdf64b10ef" +
                "86b63142a3ab8829555b2f747c932665cb2c0f1cc01bd70229388839d2af05e4" +
                "54504ac78b7582822846c0ba35c35f5c59160cc046fd8251541fc68c9c86b022" +
                "bb7099876a460e7451a8a93109703fee1c217e6c3826e52c51aa691e0e423cfc" +
                "99e9e31650c1217b624816cdad9a95f9d5b8019488d9c0a0a1fe3075a577e231" +
                "83f81d4a3f2fa4571efc8ce0ba8a4fe8b6855dfe72b0a66eded2fbabfbe58a30" +
                "fafabe1c5d71a87e2f741ef8c1fe86fea6bbfde530677f0d97d11d49f7a8443d" +
                "0822e506a9f4614e011e2a94838ff88cd68c8bb7c5c6424cffffffffffffffff"),
        };
    }
}
