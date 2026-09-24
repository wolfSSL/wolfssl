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
using System.Security.Cryptography;

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
     * Encryption, approved IV handling (IG C.H Scenario 2): call
     * UseInternalIV once, then Encrypt. The module draws the whole IV
     * (12 or 16 bytes) from its DRBG and advances it on every encryption;
     * the IV used is returned in the result. Encryption with a
     * caller-supplied IV is not offered: the module Security Policy permits
     * external IVs only for TLS (IG C.H 1(a)).
     *
     * Invocation limit (SP 800-38D 8.3): these IVs are RBG-based (8.2.2),
     * so at most 2^32 encryptions are allowed per key. The object refuses
     * the 2^32nd; the module does not enforce it for 12-byte IVs. The limit
     * is per key: encryptions under the same key in other FipsAesGcm
     * objects or FipsGmac.Compute calls count too, and staying within it
     * across objects is the application's responsibility.
     *
     * Decryption always takes the IV explicitly, runs on a separate native
     * context (so it can never change the encryption IV state) and throws
     * WolfCryptFipsException with AES_GCM_AUTH_E on tag mismatch. */
    public sealed class FipsAesGcm : FipsObject
    {
        public const int DefaultIVSize = 12;
        /* Minimum DRBG-generated part of an internal IV (96 bits). */
        public const int MinRandomIVSize = 12;
        /* Fixed field length the module accepts (AES_IV_FIXED_SZ). */
        public const int FixedFieldSize = 4;
        public const int MaxTagSize = 16;
        /* SP 800-38D 8.3: invocations allowed per key with RBG-based IVs. */
        public const ulong MaxInvocations = 1UL << 32;

        private int internalIvSize;
        private bool ivSelected;
        private ulong invocations;
        private readonly GcmContext decryptor;
        private readonly object sync = new object();

        /* Second keyed Aes context used only for decryption. */
        private sealed class GcmContext : FipsObject
        {
            internal GcmContext(byte[] key) : base(FipsStructType.Aes)
            {
                int ret = Native.wc_AesGcmSetKey_fips(Handle, key, (uint)key.Length);
                if (ret != 0) {
                    Dispose();
                    throw new WolfCryptFipsException("wc_AesGcmSetKey_fips", ret);
                }
            }
        }

        public FipsAesGcm(byte[] key) : base(FipsStructType.Aes)
        {
            if (key == null) {
                Dispose();
                throw new ArgumentNullException(nameof(key));
            }
            int ret = Native.wc_AesGcmSetKey_fips(Handle, key, (uint)key.Length);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_AesGcmSetKey_fips", ret);
            }
            try {
                decryptor = new GcmContext(key);
            }
            catch {
                Dispose();
                throw;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                decryptor?.Dispose();
            base.Dispose(disposing);
        }

        /* Encryptions made by this object (test hook for the 8.3 limit). */
        internal ulong Invocations
        {
            get { lock (sync) return invocations; }
            set { lock (sync) invocations = value; }
        }

        /* Selects module-generated IVs of ivSize bytes (12 or 16), drawn
         * entirely from rng (IG C.H Scenario 2). Once per object: the IV
         * construction and its invocation count are fixed for the object's
         * life (SP 800-38D 8.2.2, 8.3). */
        public void UseInternalIV(FipsRng rng, int ivSize = DefaultIVSize) => SelectIV(rng, ivSize, null);

        /* SP 800-38D 8.2.1-style fixed field (exactly 4 bytes, 16-byte IV so
         * at least 96 random bits remain). Internal: not an IG C.H Scenario 2
         * construction; used for ACVP testing of the module's 8.2.1 path. */
        internal void UseInternalIV(FipsRng rng, int ivSize, byte[]? fixedField) => SelectIV(rng, ivSize, fixedField);

        private void SelectIV(FipsRng rng, int ivSize, byte[]? fixedField)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            CheckInternalIVSize(ivSize);
            if (fixedField != null && (fixedField.Length != FixedFieldSize || ivSize - fixedField.Length < MinRandomIVSize))
                throw new ArgumentException("a GCM internal-IV fixed field must be exactly " + FixedFieldSize +
                    " bytes with a 16-byte IV (at least 12 random bytes); pass null for none", nameof(fixedField));
            lock (sync) {
                ThrowIfDisposed();
                if (ivSelected)
                    throw new InvalidOperationException("UseInternalIV may be called once per FipsAesGcm; " +
                        "create a new object to start a new IV sequence");
                using (rng.Use())
                    WolfCryptFipsException.Check("wc_AesGcmSetIV_fips",
                        Native.wc_AesGcmSetIV_fips(Handle, (uint)ivSize, fixedField,
                            fixedField == null ? 0u : (uint)fixedField.Length, rng.Handle));
                internalIvSize = ivSize;
                ivSelected = true;
            }
        }

        /* Encrypts with the next module-generated IV (see UseInternalIV). */
        public FipsAeadResult Encrypt(byte[] plaintext, byte[]? aad = null, int tagSize = MaxTagSize)
        {
            lock (sync) {
                if (internalIvSize == 0)
                    throw new InvalidOperationException("call UseInternalIV before Encrypt");
                if (invocations >= MaxInvocations)
                    throw new InvalidOperationException("2^32 GCM encryptions reached for this key " +
                        "(SP 800-38D 8.3); use a new key");
                /* counted before the call: an attempt may consume an IV */
                invocations++;
                return EncryptCurrent(plaintext, aad, tagSize, internalIvSize);
            }
        }

        /* SP 800-38D approved tag lengths under the module's 96-bit floor
         * are 12 to 16 bytes. */
        public const int MinTagSize = 12;

        internal static void CheckTag(byte[] tag, int tagSize)
        {
            if (tagSize < MinTagSize || tagSize > MaxTagSize)
                throw new ArgumentOutOfRangeException(nameof(tagSize), "GCM tag size must be 12 to 16 bytes");
            if (tag.Length != tagSize)
                throw new ArgumentException("tag must be " + tagSize + " bytes", nameof(tag));
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
         * Internal: used for known-answer testing only. The object cannot
         * switch to internal IVs afterwards. */
        internal FipsAeadResult EncryptWithIV(byte[] iv, byte[] plaintext, byte[]? aad = null,
                                            int tagSize = MaxTagSize)
        {
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            lock (sync) {
                ThrowIfDisposed();
                WolfCryptFipsException.Check("wc_AesGcmSetExtIV_fips",
                    Native.wc_AesGcmSetExtIV_fips(Handle, iv, (uint)iv.Length));
                internalIvSize = 0;
                ivSelected = true;
                return EncryptCurrent(plaintext, aad, tagSize, iv.Length);
            }
        }

        private FipsAeadResult EncryptCurrent(byte[] plaintext, byte[]? aad, int tagSize, int ivSize)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            ThrowIfDisposed();
            if (tagSize < MinTagSize || tagSize > MaxTagSize)
                throw new ArgumentOutOfRangeException(nameof(tagSize), "GCM tag size must be 12 to 16 bytes");
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
         * verify. tagSize is the tag length the protocol expects (12 to 16
         * bytes, default 16); the received tag must have exactly that length.
         * The module itself accepts tags of any length from 1 byte on
         * decrypt, so a truncated tag would otherwise weaken the check. */
        public byte[] Decrypt(byte[] iv, byte[] ciphertext, byte[] tag, byte[]? aad = null, int tagSize = MaxTagSize)
        {
            if (iv == null || ciphertext == null || tag == null)
                throw new ArgumentNullException(iv == null ? nameof(iv) : ciphertext == null ? nameof(ciphertext) : nameof(tag));
            CheckTag(tag, tagSize);
            ThrowIfDisposed();
            aad ??= Array.Empty<byte>();
            byte[] pt = new byte[ciphertext.Length];
            int ret;
            lock (sync) {
                decryptor.ThrowIfDisposed();
                ret = Native.wc_AesGcmDecrypt_fips(decryptor.Handle, pt, ciphertext, (uint)ciphertext.Length,
                    iv, (uint)iv.Length, tag, (uint)tag.Length, aad, (uint)aad.Length);
            }
            if (ret != 0) {
                /* some module paths decrypt before checking the tag */
                CryptographicOperations.ZeroMemory(pt);
                throw new WolfCryptFipsException("wc_AesGcmDecrypt_fips", ret);
            }
            return pt;
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
            if (tagSize < FipsAesGcm.MinTagSize || tagSize > FipsAesGcm.MaxTagSize)
                throw new ArgumentOutOfRangeException(nameof(tagSize), "GMAC tag size must be 12 to 16 bytes");
            byte[] iv = new byte[ivSize];
            byte[] tag = new byte[tagSize];
            using (rng.Use())
                WolfCryptFipsException.Check("wc_Gmac_fips",
                    Native.wc_Gmac_fips(key, (uint)key.Length, iv, (uint)iv.Length, aad, (uint)aad.Length,
                        tag, (uint)tag.Length, rng.Handle));
            return new FipsAeadResult(iv, Array.Empty<byte>(), tag);
        }

        /* True if tag is a valid GMAC of aad under key and iv. tagSize is the
         * expected tag length (12 to 16 bytes, default 16); a tag of any
         * other length is refused, since the module accepts truncated tags
         * on verification. */
        public static bool Verify(byte[] key, byte[] iv, byte[] aad, byte[] tag, int tagSize = FipsAesGcm.MaxTagSize)
        {
            if (key == null || iv == null || aad == null || tag == null)
                throw new ArgumentNullException(key == null ? nameof(key) : iv == null ? nameof(iv) : aad == null ? nameof(aad) : nameof(tag));
            FipsAesGcm.CheckTag(tag, tagSize);
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("AES key must be 16, 24 or 32 bytes", nameof(key));
            if (iv.Length == 0)
                throw new ArgumentException("IV must not be empty", nameof(iv));
            int ret = Native.wc_GmacVerify_fips(key, (uint)key.Length, iv, (uint)iv.Length,
                aad, (uint)aad.Length, tag, (uint)tag.Length);
            /* only a tag mismatch is "does not verify"; anything else
             * (module state, bad arguments) throws */
            if (ret == FipsError.AES_GCM_AUTH_E)
                return false;
            WolfCryptFipsException.Check("wc_GmacVerify_fips", ret);
            return true;
        }
    }

    /* AES-CCM (SP 800-38C) from the FIPS module. Tags are 8 to 16 bytes:
     * 32 and 48-bit tags need a separate risk analysis (SP 800-38C App. B)
     * and are not offered.
     *
     * Encryption: SetNonce once per object (a second call is refused, since
     * it would restart the module's nonce sequence), then Encrypt. The
     * module uses the nonce and increments it after each encryption; the
     * nonce used is returned in the result. SetNonce(rng) draws the initial
     * nonce from the module DRBG and is the default choice; SetNonce(nonce)
     * leaves nonce uniqueness under the key (SP 800-38C) to the caller.
     * Decryption takes the nonce explicitly and throws (AES_CCM_AUTH_E) on
     * tag mismatch. */
    public sealed class FipsAesCcm : FipsObject
    {
        private int activeNonceSize;   /* 0 until SetNonce succeeds */
        private readonly object sync = new object();

        public FipsAesCcm(byte[] key) : base(FipsStructType.Aes)
        {
            if (key == null) {
                Dispose();
                throw new ArgumentNullException(nameof(key));
            }
            int ret = Native.wc_AesCcmSetKey_fips(Handle, key, (uint)key.Length);
            if (ret != 0) {
                Dispose();
                throw new WolfCryptFipsException("wc_AesCcmSetKey_fips", ret);
            }
        }

        public const int DefaultNonceSize = 12;
        public const int MinRandomNonceSize = 12;

        /* Draws the initial nonce from the module DRBG. At least 12 bytes, so
         * random nonces of independent objects under one key collide only
         * after about 2^48 objects (SP 800-38C 5.3); 12 bytes limit each
         * payload to 2^24 - 1 bytes, 13 to 65,535. */
        public void SetNonce(FipsRng rng, int nonceSize = DefaultNonceSize)
        {
            if (rng == null)
                throw new ArgumentNullException(nameof(rng));
            if (nonceSize < MinRandomNonceSize || nonceSize > 13)
                throw new ArgumentOutOfRangeException(nameof(nonceSize), "a DRBG CCM nonce must be 12 or 13 bytes");
            /* state checks first, so a refused call draws no DRBG output */
            ThrowIfDisposed();
            ThrowIfNonceSet();
            byte[] nonce = rng.Generate(nonceSize);
            SetNonce(nonce);
        }

        /* nonce: 7 to 13 bytes, unique under this key. */
        public void SetNonce(byte[] nonce)
        {
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));
            ThrowIfDisposed();
            lock (sync) {
                ThrowIfNonceSet();
                WolfCryptFipsException.Check("wc_AesCcmSetNonce_fips",
                    Native.wc_AesCcmSetNonce_fips(Handle, nonce, (uint)nonce.Length));
                activeNonceSize = nonce.Length;
            }
        }

        private void ThrowIfNonceSet()
        {
            if (activeNonceSize != 0)
                throw new InvalidOperationException("SetNonce may be called once per FipsAesCcm; " +
                    "create a new object to start a new nonce sequence");
        }

        public const int MinTagSize = 8;

        private static void CheckTagSize(int tagSize)
        {
            if (tagSize < MinTagSize || tagSize > 16 || tagSize % 2 != 0)
                throw new ArgumentOutOfRangeException(nameof(tagSize), "CCM tag must be 8, 10, 12, 14 or 16 bytes");
        }

        /* CCM encodes the payload length in 15 - nonceSize bytes and uses the
         * same bytes as the block counter (SP 800-38C A.1), so the payload
         * must be shorter than 2^(8*(15-nonceSize)) bytes. The v5.2.x module
         * does not check this (longer inputs wrap the counter and reuse
         * keystream). */
        private static void CheckPayloadLength(int payloadLen, int nonceLen)
        {
            int lenBytes = 15 - nonceLen;
            if (lenBytes < 4 && (long)payloadLen >= (1L << (8 * lenBytes)))
                throw new ArgumentException("CCM payload too long for a " + nonceLen + "-byte nonce (limit " +
                    ((1L << (8 * lenBytes)) - 1) + " bytes)");
        }

        public FipsAeadResult Encrypt(byte[] plaintext, byte[]? aad = null, int tagSize = 16)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            CheckTagSize(tagSize);
            if (activeNonceSize == 0)
                throw new InvalidOperationException("call SetNonce before Encrypt");
            CheckPayloadLength(plaintext.Length, activeNonceSize);
            ThrowIfDisposed();
            aad ??= Array.Empty<byte>();
            byte[] ct = new byte[plaintext.Length];
            byte[] nonce = new byte[activeNonceSize];
            byte[] tag = new byte[tagSize];
            lock (sync)   /* the module advances the nonce: one encryption at a time */
                WolfCryptFipsException.Check("wc_AesCcmEncrypt_fips",
                    Native.wc_AesCcmEncrypt_fips(Handle, ct, plaintext, (uint)plaintext.Length,
                        nonce, (uint)nonce.Length, tag, (uint)tag.Length, aad, (uint)aad.Length));
            return new FipsAeadResult(nonce, ct, tag);
        }

        /* tagSize is the tag length the receiver expects; a tag of any
         * other length is refused (as for GCM), so a shorter tag cannot
         * lower the forgery bound. */
        public byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[]? aad = null, int tagSize = 16)
        {
            if (nonce == null || ciphertext == null || tag == null)
                throw new ArgumentNullException(nonce == null ? nameof(nonce) : ciphertext == null ? nameof(ciphertext) : nameof(tag));
            CheckTagSize(tagSize);
            if (tag.Length != tagSize)
                throw new ArgumentException("tag must be " + tagSize + " bytes", nameof(tag));
            if (nonce.Length < 7 || nonce.Length > 13)
                throw new ArgumentException("CCM nonce must be 7 to 13 bytes", nameof(nonce));
            CheckPayloadLength(ciphertext.Length, nonce.Length);
            ThrowIfDisposed();
            aad ??= Array.Empty<byte>();
            byte[] pt = new byte[ciphertext.Length];
            int ret = Native.wc_AesCcmDecrypt_fips(Handle, pt, ciphertext, (uint)ciphertext.Length,
                nonce, (uint)nonce.Length, tag, (uint)tag.Length, aad, (uint)aad.Length);
            if (ret != 0) {
                CryptographicOperations.ZeroMemory(pt);
                throw new WolfCryptFipsException("wc_AesCcmDecrypt_fips", ret);
            }
            return pt;
        }
    }
}
