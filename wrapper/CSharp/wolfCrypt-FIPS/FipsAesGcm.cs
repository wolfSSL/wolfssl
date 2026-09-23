/* FipsAesGcm.cs
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
    /* Result of an authenticated encryption: the IV/nonce actually used,
     * the ciphertext and the authentication tag. */
    public sealed class FipsAeadResult
    {
        public byte[] IV { get; }
        public byte[] Ciphertext { get; }
        public byte[] Tag { get; }

        internal FipsAeadResult(byte[] iv, byte[] ct, byte[] tag)
        {
            IV = iv;
            Ciphertext = ct;
            Tag = tag;
        }
    }

    /* AES-GCM (SP 800-38D) from the FIPS module.
     *
     * Encryption, approved IV handling: call UseInternalIV once, then
     * Encrypt. The module builds each IV from the fixed field and its DRBG
     * and advances an invocation counter on every encryption; the IV used is
     * returned in the result.
     *
     * IVs are at least 96 bits (IG C.H Scenario 2): 12 or 16 bytes.
     * Encryption with a caller-supplied IV is not offered: the module
     * Security Policy permits external IVs only for TLS (IG C.H 1(a)).
     *
     * Decryption always takes the IV explicitly and throws
     * WolfCryptFipsException with AES_GCM_AUTH_E on tag mismatch. */
    public sealed class FipsAesGcm : FipsObject
    {
        public const int DefaultIVSize = 12;
        public const int MaxTagSize = 16;
        private int internalIvSize;

        public FipsAesGcm(byte[] key) : base(FipsStructType.Aes)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            int ret = Native.wc_AesGcmSetKey_fips(Handle, key, (uint)key.Length);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_AesGcmSetKey_fips", ret);
            }
        }

        /* Selects module-generated IVs of ivSize bytes (12 or 16).
         * fixedField (null or 4 bytes) forms the leading bytes of each IV;
         * the rest comes from rng. */
        public void UseInternalIV(FipsRng rng, int ivSize = DefaultIVSize, byte[]? fixedField = null)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            CheckInternalIVSize(ivSize);
            ThrowIfDisposed();
            rng.ThrowIfDisposed();
            WolfCryptFipsException.Check("wc_AesGcmSetIV_fips",
                Native.wc_AesGcmSetIV_fips(Handle, (uint)ivSize, fixedField,
                    fixedField == null ? 0u : (uint)fixedField.Length, rng.Handle));
            internalIvSize = ivSize;
        }

        /* Encrypts with the next module-generated IV (see UseInternalIV). */
        public FipsAeadResult Encrypt(byte[] plaintext, byte[]? aad = null, int tagSize = MaxTagSize)
        {
            if (internalIvSize == 0)
                throw new InvalidOperationException("call UseInternalIV before Encrypt");
            return EncryptCurrent(plaintext, aad, tagSize, internalIvSize);
        }

        /* IG C.H Scenario 2: an internally generated random IV shall be at
         * least 96 bits. The module also accepts 8-byte IVs, so this is
         * checked here. */
        internal static void CheckInternalIVSize(int ivSize)
        {
            if (ivSize != 12 && ivSize != 16)
                throw new ArgumentOutOfRangeException(nameof(ivSize),
                    "internally generated GCM IVs must be 12 or 16 bytes (at least 96 bits)");
        }

        /* Encrypts with a caller-supplied IV (wc_AesGcmSetExtIV_fips).
         * Internal: used for known-answer testing only. */
        internal FipsAeadResult EncryptWithIV(byte[] iv, byte[] plaintext, byte[]? aad = null,
                                            int tagSize = MaxTagSize)
        {
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            ThrowIfDisposed();
            WolfCryptFipsException.Check("wc_AesGcmSetExtIV_fips",
                Native.wc_AesGcmSetExtIV_fips(Handle, iv, (uint)iv.Length));
            internalIvSize = 0;
            return EncryptCurrent(plaintext, aad, tagSize, iv.Length);
        }

        private FipsAeadResult EncryptCurrent(byte[] plaintext, byte[]? aad, int tagSize, int ivSize)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            ThrowIfDisposed();
            aad ??= Array.Empty<byte>();
            byte[] ct = new byte[plaintext.Length];
            byte[] ivOut = new byte[ivSize];
            byte[] tag = new byte[tagSize];
            WolfCryptFipsException.Check("wc_AesGcmEncrypt_fips",
                Native.wc_AesGcmEncrypt_fips(Handle, ct, plaintext, (uint)plaintext.Length,
                    ivOut, (uint)ivOut.Length, tag, (uint)tag.Length, aad, (uint)aad.Length));
            return new FipsAeadResult(ivOut, ct, tag);
        }

        /* Returns the plaintext; throws (AES_GCM_AUTH_E) if the tag does not
         * verify. */
        public byte[] Decrypt(byte[] iv, byte[] ciphertext, byte[] tag, byte[]? aad = null)
        {
            if (iv == null || ciphertext == null || tag == null)
                throw new ArgumentNullException(iv == null ? nameof(iv) : ciphertext == null ? nameof(ciphertext) : nameof(tag));
            ThrowIfDisposed();
            aad ??= Array.Empty<byte>();
            byte[] pt = new byte[ciphertext.Length];
            WolfCryptFipsException.Check("wc_AesGcmDecrypt_fips",
                Native.wc_AesGcmDecrypt_fips(Handle, pt, ciphertext, (uint)ciphertext.Length,
                    iv, (uint)iv.Length, tag, (uint)tag.Length, aad, (uint)aad.Length));
            return pt;
        }

        protected override void FreeNative()
        {
            /* no wc_AesFree in the v5.2.3 boundary */
        }
    }

    /* GMAC (SP 800-38D authentication-only mode) from the FIPS module. */
    public static class FipsGmac
    {
        /* Generates a tag over aad with a module-generated IV of ivSize bytes
         * (drawn from rng). Returns the IV and tag. */
        public static FipsAeadResult Compute(byte[] key, byte[] aad, FipsRng rng,
                                             int ivSize = FipsAesGcm.DefaultIVSize,
                                             int tagSize = FipsAesGcm.MaxTagSize)
        {
            if (key == null || aad == null || rng == null)
                throw new ArgumentNullException(key == null ? nameof(key) : aad == null ? nameof(aad) : nameof(rng));
            FipsAesGcm.CheckInternalIVSize(ivSize);
            rng.ThrowIfDisposed();
            byte[] iv = new byte[ivSize];
            byte[] tag = new byte[tagSize];
            WolfCryptFipsException.Check("wc_Gmac_fips",
                Native.wc_Gmac_fips(key, (uint)key.Length, iv, (uint)iv.Length, aad, (uint)aad.Length,
                    tag, (uint)tag.Length, rng.Handle));
            return new FipsAeadResult(iv, Array.Empty<byte>(), tag);
        }

        /* True if tag is a valid GMAC of aad under key and iv. */
        public static bool Verify(byte[] key, byte[] iv, byte[] aad, byte[] tag)
        {
            if (key == null || iv == null || aad == null || tag == null)
                throw new ArgumentNullException();
            int ret = Native.wc_GmacVerify_fips(key, (uint)key.Length, iv, (uint)iv.Length,
                aad, (uint)aad.Length, tag, (uint)tag.Length);
            if (ret == FipsError.AES_GCM_AUTH_E || (ret != 0 && !FipsError.IsModuleStateError(ret)))
                return false;
            WolfCryptFipsException.Check("wc_GmacVerify_fips", ret);
            return true;
        }
    }

    /* AES-CCM (SP 800-38C) from the FIPS module. Tags are 8 to 16 bytes:
     * 32 and 48-bit tags need a separate risk analysis (SP 800-38C App. B)
     * and are not offered.
     *
     * Encryption: SetNonce once, then Encrypt. The module uses the nonce and
     * increments it after each encryption; the nonce used is returned in the
     * result. Decryption takes the nonce explicitly and throws
     * (AES_CCM_AUTH_E) on tag mismatch. */
    public sealed class FipsAesCcm : FipsObject
    {
        private int nonceSize;

        public FipsAesCcm(byte[] key) : base(FipsStructType.Aes)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            int ret = Native.wc_AesCcmSetKey_fips(Handle, key, (uint)key.Length);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_AesCcmSetKey_fips", ret);
            }
        }

        /* nonce: 7 to 13 bytes. */
        public void SetNonce(byte[] nonce)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));
            ThrowIfDisposed();
            WolfCryptFipsException.Check("wc_AesCcmSetNonce_fips",
                Native.wc_AesCcmSetNonce_fips(Handle, nonce, (uint)nonce.Length));
            nonceSize = nonce.Length;
        }

        public const int MinTagSize = 8;

        private static void CheckTagSize(int tagSize)
        {
            if (tagSize < MinTagSize || tagSize > 16 || tagSize % 2 != 0)
                throw new ArgumentOutOfRangeException(nameof(tagSize), "CCM tag must be 8, 10, 12, 14 or 16 bytes");
        }

        public FipsAeadResult Encrypt(byte[] plaintext, byte[]? aad = null, int tagSize = 16)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            CheckTagSize(tagSize);
            if (nonceSize == 0)
                throw new InvalidOperationException("call SetNonce before Encrypt");
            ThrowIfDisposed();
            aad ??= Array.Empty<byte>();
            byte[] ct = new byte[plaintext.Length];
            byte[] nonce = new byte[nonceSize];
            byte[] tag = new byte[tagSize];
            WolfCryptFipsException.Check("wc_AesCcmEncrypt_fips",
                Native.wc_AesCcmEncrypt_fips(Handle, ct, plaintext, (uint)plaintext.Length,
                    nonce, (uint)nonce.Length, tag, (uint)tag.Length, aad, (uint)aad.Length));
            return new FipsAeadResult(nonce, ct, tag);
        }

        public byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[]? aad = null)
        {
            if (nonce == null || ciphertext == null || tag == null)
                throw new ArgumentNullException();
            CheckTagSize(tag.Length);
            ThrowIfDisposed();
            aad ??= Array.Empty<byte>();
            byte[] pt = new byte[ciphertext.Length];
            WolfCryptFipsException.Check("wc_AesCcmDecrypt_fips",
                Native.wc_AesCcmDecrypt_fips(Handle, pt, ciphertext, (uint)ciphertext.Length,
                    nonce, (uint)nonce.Length, tag, (uint)tag.Length, aad, (uint)aad.Length));
            return pt;
        }

        protected override void FreeNative()
        {
            /* no wc_AesFree in the v5.2.3 boundary */
        }
    }
}
