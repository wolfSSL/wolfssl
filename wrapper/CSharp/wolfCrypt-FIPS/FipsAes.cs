/* FipsAes.cs
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

namespace wolfSSL.CSharp.Fips
{
    public enum FipsAesMode { Ecb, Cbc, Ctr, Ofb }

    /* AES ECB/CBC/CTR/OFB (FIPS 197, SP 800-38A). One encryptor per message: after it the CBC
     * chaining state is predictable, so use a new object and DRBG IV (SP 800-38A App. C).
     * ECB is a building block only. v5.2.1 has no AES free; the key is zeroed on Dispose. */
    public sealed class FipsAes : FipsObject
    {
        public const int BlockSize = 16;
        private const int AES_ENCRYPTION = 0;
        private const int AES_DECRYPTION = 1;

        public FipsAesMode Mode { get; }
        public bool Encrypting { get; }

        /* IV (initial counter block) from creation or the last SetIV, not the chaining state
         * after Transform. Null for ECB; returns a copy. */
        public byte[]? IV => iv == null ? null : (byte[])iv.Clone();
        private byte[]? iv;
        private bool drbgIV;
        private readonly object sync = new object();

        private FipsAes(FipsAesMode mode, bool encrypt, byte[] key, byte[]? iv) : base(FipsStructType.Aes)
        {
            if (key == null)
            {
                Dispose();
                throw new ArgumentNullException(nameof(key));
            }
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                Dispose();
                throw new ArgumentException("AES key must be 16, 24 or 32 bytes", nameof(key));
            }
            if (mode != FipsAesMode.Ecb && (iv == null || iv.Length != BlockSize))
            {
                Dispose();
                throw new ArgumentException("IV must be 16 bytes", nameof(iv));
            }
            Mode = mode;
            Encrypting = encrypt;
            this.iv = iv == null ? null : (byte[])iv.Clone();
            int ret;
            string fn;
            if (mode == FipsAesMode.Ctr)
            {
                /* CTR (and OFB) use the forward cipher in both directions */
                fn = "wc_AesCtrSetKey_fips";
                ret = Native.wc_AesCtrSetKey_fips(Handle, key, (uint)key.Length, iv, AES_ENCRYPTION);
            }
            else
            {
                fn = "wc_AesSetKey_fips";
                int dir = (mode == FipsAesMode.Ofb || encrypt) ? AES_ENCRYPTION : AES_DECRYPTION;
                ret = Native.wc_AesSetKey_fips(Handle, key, (uint)key.Length, iv, dir);
            }
            if (ret != 0)
            {
                Dispose();
                throw new WolfCryptFipsException(fn, ret);
            }
        }

        /* SP 800-38A: CBC IV unpredictable, OFB IV and CTR counter blocks unique per key. The
         * FipsRng overloads draw the IV from the DRBG (read it from IV) and are the encryption
         * paths; with a caller IV, CBC only decrypts and OFB/CTR uniqueness is the caller's job. */
        public static FipsAes CreateEcb(byte[] key, bool encrypt) => new FipsAes(FipsAesMode.Ecb, encrypt, key, null);
        public static FipsAes CreateCbc(byte[] key, FipsRng rng) => WithDrbgIV(new FipsAes(FipsAesMode.Cbc, true, key, NewIV(rng)));
        public static FipsAes CreateOfb(byte[] key, FipsRng rng) => WithDrbgIV(new FipsAes(FipsAesMode.Ofb, true, key, NewIV(rng)));
        public static FipsAes CreateCtr(byte[] key, FipsRng rng) => WithDrbgIV(new FipsAes(FipsAesMode.Ctr, true, key, NewIV(rng)));

        private static FipsAes WithDrbgIV(FipsAes a)
        {
            a.drbgIV = true;
            return a;
        }

        private static byte[] NewIV(FipsRng rng)
        {
            if (rng == null)
            {
                throw new ArgumentNullException(nameof(rng));
            }

            return rng.Generate(BlockSize);
        }

        /* CBC decryption with the IV that came with the ciphertext. */
        public static FipsAes CreateCbcDecryptor(byte[] key, byte[] iv) => new FipsAes(FipsAesMode.Cbc, false, key, iv);

        /* CBC with a caller IV in either direction. Internal, for known-answer testing: a
         * caller-chosen IV cannot be guaranteed unpredictable for encryption. */
        internal static FipsAes CreateCbc(byte[] key, byte[] iv, bool encrypt) => new FipsAes(FipsAesMode.Cbc, encrypt, key, iv);
        public static FipsAes CreateOfb(byte[] key, byte[] iv, bool encrypt) => new FipsAes(FipsAesMode.Ofb, encrypt, key, iv);
        /* iv is the initial counter block, the whole 16 bytes (m = 128); with a nonce || counter
         * layout keep each message under 2^m blocks for the counter width m you reserve. */
        public static FipsAes CreateCtr(byte[] key, byte[] iv) => new FipsAes(FipsAesMode.Ctr, true, key, iv);

        /* Processes input and returns output of the same length. */
        public byte[] Transform(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            ThrowIfDisposed();
            /* without WOLFSSL_AES_CBC_LENGTH_CHECKS the module processes only whole blocks,
             * returns success and leaves the tail of the output zero */
            if ((Mode == FipsAesMode.Ecb || Mode == FipsAesMode.Cbc) && input.Length % BlockSize != 0)
            {
                throw new ArgumentException(Mode + " input must be a multiple of 16 bytes", nameof(input));
            }

            byte[] output = GC.AllocateArray<byte>(input.Length, pinned: true);   /* may be plaintext */
            uint sz = (uint)input.Length;
            int ret;
            string fn;
            lock (sync)
            {
                ThrowIfDisposed();
                switch (Mode)
                {
                    case FipsAesMode.Ecb:
                        fn = Encrypting ? "wc_AesEcbEncrypt_fips" : "wc_AesEcbDecrypt_fips";
                        ret = Encrypting ? Native.wc_AesEcbEncrypt_fips(Handle, output, input, sz)
                                         : Native.wc_AesEcbDecrypt_fips(Handle, output, input, sz);
                        break;
                    case FipsAesMode.Cbc:
                        fn = Encrypting ? "wc_AesCbcEncrypt_fips" : "wc_AesCbcDecrypt_fips";
                        ret = Encrypting ? Native.wc_AesCbcEncrypt_fips(Handle, output, input, sz)
                                         : Native.wc_AesCbcDecrypt_fips(Handle, output, input, sz);
                        break;
                    case FipsAesMode.Ofb:
                        fn = Encrypting ? "wc_AesOfbEncrypt_fips" : "wc_AesOfbDecrypt_fips";
                        ret = Encrypting ? Native.wc_AesOfbEncrypt_fips(Handle, output, input, sz)
                                         : Native.wc_AesOfbDecrypt_fips(Handle, output, input, sz);
                        break;
                    default:
                        fn = "wc_AesCtrEncrypt_fips";
                        ret = Native.wc_AesCtrEncrypt_fips(Handle, output, input, sz);
                        break;
                }
            }
            WolfCryptFipsException.Check(fn, ret);
            return output;
        }

        /* Resets the CBC chaining value to iv, for decrypting the next message. CBC decryptors
         * only: an encryptor IV must not be caller-chosen (SP 800-38A App. C), and OFB/CTR keep
         * buffered keystream that wc_AesSetIV does not reset. */
        public void SetIV(byte[] iv)
        {
            if (iv == null || iv.Length != BlockSize)
            {
                throw new ArgumentException("IV must be 16 bytes", nameof(iv));
            }

            ThrowIfDisposed();
            if (Mode != FipsAesMode.Cbc)
            {
                throw new InvalidOperationException("SetIV is supported for CBC only; create a new " + Mode + " object");
            }

            if (Encrypting || drbgIV)
            {
                throw new InvalidOperationException("the IV of a CBC encryptor cannot be replaced; " +
                    "create a new encryptor (new DRBG IV) for each message");
            }

            lock (sync)
            {
                ThrowIfDisposed();
                WolfCryptFipsException.Check("wc_AesSetIV_fips", Native.wc_AesSetIV_fips(Handle, iv));
                this.iv = (byte[])iv.Clone();
            }
        }
    }
}
