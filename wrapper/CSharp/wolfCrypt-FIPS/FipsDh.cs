/* FipsDh.cs
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
    /* RFC 7919 groups as the module's WC_FFDHE_* ids. The #4718 Security Policy lists
     * KAS-FFC-SSC (dhEphem) with ffdhe2048 only; the module's ffdhe3072..8192 are not offered. */
    public enum FipsDhGroup
    {
        Ffdhe2048 = 256
    }

    public sealed class FipsDhKeyPair : IDisposable
    {
        public byte[] PrivateKey { get; }
        public byte[] PublicKey { get; }
        internal FipsDhKeyPair(byte[] priv, byte[] pub) { PrivateKey = priv; PublicKey = pub; }
        /* Zeroes the private key. */
        public void Dispose() => CryptographicOperations.ZeroMemory(PrivateKey);
    }

    /* Finite field Diffie-Hellman (SP 800-56A) from the FIPS module. The
     * object holds the domain parameters; key pairs and peer public keys
     * are byte arrays, as in the module API. */
    public sealed class FipsDh : FipsObject
    {

        /* Prime size in bytes. */
        public int PrimeSize { get; }

        /* Subgroup order q for explicit domains; the module checks y^q = 1 only for a q passed in.
         * Null for the named group: range check 2 <= y <= p-2 only (partial validation, SP 800-56A
         * 5.6.2.3.2, allowed by 5.6.2.2.2 for ephemeral keys of a safe-prime group). */
        private readonly byte[]? q;

        /* RFC 7919 safe-prime group (KAS-FFC-SSC, dhEphem): ffdhe2048. */
        public FipsDh(FipsDhGroup group) : this(group, validatedOnly: true)
        {
        }

        /* Any RFC 7919 group the module implements, including those outside
         * the validated KAS-FFC-SSC. Internal: for ACVP known-answer tests. */
        internal static FipsDh AnyNamedGroup(FipsDhGroup group) => new FipsDh(group, validatedOnly: false);

        private FipsDh(FipsDhGroup group, bool validatedOnly) : base(FipsStructType.Dh)
        {
            if (validatedOnly && group != FipsDhGroup.Ffdhe2048)
            {
                Dispose();
                throw new ArgumentException("KAS-FFC-SSC is validated for ffdhe2048 only (SP #4718)", nameof(group));
            }
            Init();
            Call("wc_DhSetNamedKey_fips", Native.wc_DhSetNamedKey_fips(Handle, (int)group));
            PrimeSize = (int)group switch { 256 => 256, 257 => 384, 258 => 512, 259 => 768, _ => 1024 };
        }

        /* Internal, for testing explicit FIPS 186-type domains; not an approved service (the
         * validated KAS-FFC-SSC, SP #4718, covers RFC 7919 groups only). SP 800-131A Rev. 2
         * Table 4 allows only (len(p), len(q)) = (2048, 224) or (2048, 256). */
        internal FipsDh(byte[] p, byte[] g, byte[] q) : base(FipsStructType.Dh)
        {
            if (p == null || g == null || q == null)
            {
                Dispose();
                throw new ArgumentNullException(p == null ? nameof(p) : g == null ? nameof(g) : nameof(q));
            }
            int pBits = BitLength(p), qBits = BitLength(q);
            if (pBits != 2048 || (qBits != 224 && qBits != 256))
            {
                Dispose();
                throw new ArgumentException("DH domain parameters must be (len(p), len(q)) = (2048, 224) or (2048, 256)");
            }
            /* The module only checks that p is prime; a composite q would let small-order keys
             * pass y^q = 1, so only the published RFC 5114 2.2 and 2.3 groups are accepted. */
            if (!KnownDomains.Any(d => SameValue(d.P, p) && SameValue(d.G, g) && SameValue(d.Q, q)))
            {
                Dispose();
                throw new ArgumentException("explicit DH domain parameters must be an RFC 5114 2048-bit group " +
                    "(section 2.2 or 2.3); the module cannot validate other domains");
            }
            Init();
            Call("wc_DhSetKeyEx_fips", Native.wc_DhSetKeyEx_fips(Handle, p, (uint)p.Length, g, (uint)g.Length,
                q, (uint)q.Length));
            this.q = (byte[])q.Clone();
            PrimeSize = p.SkipWhile(b => b == 0).Count();
        }

        private static readonly (byte[] P, byte[] G, byte[] Q)[] KnownDomains = {
            /* RFC 5114 2.2: 2048-bit MODP group, 224-bit prime order subgroup */
            (Convert.FromHexString(
                "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75" +
                "E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A6" +
                "6D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207" +
                "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A3170918836" +
                "81286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074" +
                "15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8" +
                "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29" +
                "E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F"),
             Convert.FromHexString(
                "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3" +
                "A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652" +
                "BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A" +
                "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D1" +
                "19529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC" +
                "B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381" +
                "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD" +
                "7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA"),
             Convert.FromHexString(
                "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB")),
            /* RFC 5114 2.3: 2048-bit MODP group, 256-bit prime order subgroup */
            (Convert.FromHexString(
                "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00" +
                "E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C" +
                "209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B" +
                "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76" +
                "B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E" +
                "F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026" +
                "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103" +
                "A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597"),
             Convert.FromHexString(
                "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125" +
                "10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62" +
                "901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B" +
                "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193" +
                "B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A" +
                "DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915" +
                "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3" +
                "2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659"),
             Convert.FromHexString(
                "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3"))
        };

        private static bool SameValue(byte[] known, byte[] v) =>
            v.SkipWhile(b => b == 0).SequenceEqual(known);

        private static int BitLength(byte[] v)
        {
            int i = 0;
            while (i < v.Length && v[i] == 0)
            {
                i++;
            }

            if (i == v.Length)
            {
                return 0;
            }

            int bits = (v.Length - i - 1) * 8, b = v[i];
            while (b != 0) { bits++; b >>= 1; }
            return bits;
        }

        private void Init()
        {
            int ret = Native.wc_InitDhKey_fips(Handle);
            if (ret != 0)
            {
                Dispose();
                throw new WolfCryptFipsException("wc_InitDhKey_fips", ret);
            }
            SetNativeFree(p => Native.wc_FreeDhKey_fips(p));
        }

        private void Call(string fn, int ret)
        {
            if (ret != 0)
            {
                Dispose();
                throw new WolfCryptFipsException(fn, ret);
            }
        }

        /* Public key y as a fixed-length octet string, left-padded to the
         * prime size (SP 800-56A FE2OS; the module returns the minimal
         * length). */
        private byte[] PadToPrime(byte[] v, uint len)
        {
            byte[] r = new byte[PrimeSize];
            Buffer.BlockCopy(v, 0, r, PrimeSize - (int)len, (int)len);
            return r;
        }

        /* Generates a key pair (includes the module's pairwise consistency
         * test). The public key is PrimeSize bytes. */
        public FipsDhKeyPair GenerateKeyPair(FipsRng rng)
        {
            if (rng == null)
            {
                throw new ArgumentNullException(nameof(rng));
            }

            ThrowIfDisposed();
            byte[] priv = GC.AllocateArray<byte>(PrimeSize, pinned: true), pub = new byte[PrimeSize];
            uint privSz = (uint)priv.Length, pubSz = (uint)pub.Length;
            try
            {
                using (rng.Use())
                {
                    WolfCryptFipsException.Check("wc_DhGenerateKeyPair_fips", FipsModule.WithPrivateKeyRead(() =>
                        Native.wc_DhGenerateKeyPair_fips(Handle, rng.Handle, priv, ref privSz, pub, ref pubSz)));
                }

                return new FipsDhKeyPair(PinnedCopy(priv, 0, (int)privSz), PadToPrime(pub, pubSz));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(priv);
            }
        }

        /* Shared secret Z, left-padded to the prime size (SP 800-56A
         * fixed-length representation). The module validates the peer
         * public key. */
        public byte[] Agree(byte[] privateKey, byte[] peerPublicKey)
        {
            if (privateKey == null || peerPublicKey == null)
            {
                throw new ArgumentNullException(privateKey == null ? nameof(privateKey) : nameof(peerPublicKey));
            }

            ThrowIfDisposed();
            /* The module's public key check first (wc_DhCheckPubKeyEx; with
             * q for explicit domains it includes y^q = 1). */
            int chk = Native.wc_DhCheckPubKeyEx_fips(Handle, peerPublicKey, (uint)peerPublicKey.Length,
                                                     q, q == null ? 0u : (uint)q.Length);
            if (chk != 0)
            {
                throw new WolfCryptFipsException("wc_DhCheckPubKeyEx_fips", chk);
            }
            /* pinned and zeroed on every exit, including a failure to
* close the private key read gate after a successful agree */
            byte[] z = GC.AllocateArray<byte>(PrimeSize, pinned: true);
            try
            {
                uint zSz = (uint)z.Length;
                WolfCryptFipsException.Check("wc_DhAgree_fips", FipsModule.WithPrivateKeyRead(() =>
                    Native.wc_DhAgree_fips(Handle, z, ref zSz, privateKey, (uint)privateKey.Length,
                                           peerPublicKey, (uint)peerPublicKey.Length)));
                /* left-pad Z to the length of p (SP 800-56A 5.7.1.1) */
                byte[] result = GC.AllocateArray<byte>(PrimeSize, pinned: true);
                Buffer.BlockCopy(z, 0, result, PrimeSize - (int)zSz, (int)zSz);
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(z);
            }
        }

        /* Key checks return false for an invalid key and throw on module-state errors.
         * CheckPublicKey: the module's range check, plus y^q = 1 for explicit domains. */
        public bool CheckPublicKey(byte[] pub) => CheckArgs(pub, nameof(pub)) &&
            CheckResult("wc_DhCheckPubKeyEx_fips", Native.wc_DhCheckPubKeyEx_fips(Handle, pub, (uint)pub.Length,
                                                                               q, q == null ? 0u : (uint)q.Length));

        public bool CheckPrivateKey(byte[] priv) => CheckArgs(priv, nameof(priv)) &&
            CheckResult("wc_DhCheckPrivKeyEx_fips", Native.wc_DhCheckPrivKeyEx_fips(Handle, priv, (uint)priv.Length, null, 0));

        public bool CheckKeyPair(byte[] pub, byte[] priv) => CheckArgs(pub, nameof(pub)) && CheckArgs(priv, nameof(priv)) &&
            CheckResult("wc_DhCheckKeyPair_fips",
                Native.wc_DhCheckKeyPair_fips(Handle, pub, (uint)pub.Length, priv, (uint)priv.Length));

        private bool CheckArgs(byte[] v, string name)
        {
            if (v == null)
            {
                throw new ArgumentNullException(name);
            }

            ThrowIfDisposed();
            return true;
        }

        private static bool CheckResult(string fn, int ret)
        {
            if (FipsError.IsModuleStateError(ret))
            {
                throw new WolfCryptFipsException(fn, ret);
            }

            return ret == 0;
        }
    }
}
