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
    /* RFC 7919 named groups; values are the module's WC_FFDHE_* ids. */
    public enum FipsDhGroup
    {
        Ffdhe2048 = 256,
        Ffdhe3072 = 257,
        Ffdhe4096 = 258,
        Ffdhe6144 = 259,
        Ffdhe8192 = 260
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
        private bool initialized;

        /* Prime size in bytes. */
        public int PrimeSize { get; }

        public FipsDh(FipsDhGroup group) : base(FipsStructType.Dh)
        {
            Init();
            Call("wc_DhSetNamedKey_fips", Native.wc_DhSetNamedKey_fips(Handle, (int)group));
            PrimeSize = (int)group switch { 256 => 256, 257 => 384, 258 => 512, 259 => 768, _ => 1024 };
        }

        /* Explicit domain parameters p, g and q (q may be null). */
        public FipsDh(byte[] p, byte[] g, byte[]? q) : base(FipsStructType.Dh)
        {
            if (p == null || g == null)
                throw new ArgumentNullException(p == null ? nameof(p) : nameof(g));
            Init();
            Call("wc_DhSetKeyEx_fips", Native.wc_DhSetKeyEx_fips(Handle, p, (uint)p.Length, g, (uint)g.Length,
                q, q == null ? 0u : (uint)q.Length));
            PrimeSize = p.SkipWhile(b => b == 0).Count();
        }

        private void Init()
        {
            int ret = Native.wc_InitDhKey_fips(Handle);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_InitDhKey_fips", ret);
            }
            initialized = true;
        }

        private void Call(string fn, int ret)
        {
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException(fn, ret);
            }
        }

        /* Generates a key pair (includes the module's pairwise consistency
         * test). */
        public FipsDhKeyPair GenerateKeyPair(FipsRng rng)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            ThrowIfDisposed();
            rng.ThrowIfDisposed();
            byte[] priv = new byte[PrimeSize], pub = new byte[PrimeSize];
            uint privSz = (uint)priv.Length, pubSz = (uint)pub.Length;
            WolfCryptFipsException.Check("wc_DhGenerateKeyPair_fips", FipsModule.WithPrivateKeyRead(() =>
                Native.wc_DhGenerateKeyPair_fips(Handle, rng.Handle, priv, ref privSz, pub, ref pubSz)));
            var kp = new FipsDhKeyPair(priv.Take((int)privSz).ToArray(), pub.Take((int)pubSz).ToArray());
            CryptographicOperations.ZeroMemory(priv);
            return kp;
        }

        /* Computes the public key for a private key. v5.2.3 and later only;
         * throws NotSupportedException on a v5.2.1 module. */
        public byte[] GeneratePublic(byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            ThrowIfDisposed();
            byte[] pub = new byte[PrimeSize];
            uint pubSz = (uint)pub.Length;
            int ret;
            try {
                ret = Native.wc_DhGeneratePublic_fips(Handle, privateKey, (uint)privateKey.Length, pub, ref pubSz);
            }
            catch (EntryPointNotFoundException) {
                throw new NotSupportedException("wc_DhGeneratePublic_fips requires FIPS v5.2.3 or later");
            }
            WolfCryptFipsException.Check("wc_DhGeneratePublic_fips", ret);
            return pub.Take((int)pubSz).ToArray();
        }

        /* Shared secret Z, left-padded to the prime size (SP 800-56A
         * fixed-length representation). The module validates the peer
         * public key. */
        public byte[] Agree(byte[] privateKey, byte[] peerPublicKey)
        {
            if (privateKey == null || peerPublicKey == null)
                throw new ArgumentNullException(privateKey == null ? nameof(privateKey) : nameof(peerPublicKey));
            ThrowIfDisposed();
            byte[] z = new byte[PrimeSize];
            uint zSz = (uint)z.Length;
            WolfCryptFipsException.Check("wc_DhAgree_fips", FipsModule.WithPrivateKeyRead(() =>
                Native.wc_DhAgree_fips(Handle, z, ref zSz, privateKey, (uint)privateKey.Length,
                                       peerPublicKey, (uint)peerPublicKey.Length)));
            byte[] result = new byte[PrimeSize - (int)zSz].Concat(z.Take((int)zSz)).ToArray();
            CryptographicOperations.ZeroMemory(z);
            return result;
        }

        public bool CheckPublicKey(byte[] pub) =>
            Native.wc_DhCheckPubKeyEx_fips(Handle, pub, (uint)pub.Length, null, 0) == 0;

        public bool CheckPrivateKey(byte[] priv) =>
            Native.wc_DhCheckPrivKeyEx_fips(Handle, priv, (uint)priv.Length, null, 0) == 0;

        public bool CheckKeyPair(byte[] pub, byte[] priv) =>
            Native.wc_DhCheckKeyPair_fips(Handle, pub, (uint)pub.Length, priv, (uint)priv.Length) == 0;

        protected override void FreeNative()
        {
            if (initialized)
                Native.wc_FreeDhKey_fips(Handle);
        }
    }
}
