/* wolfCrypt-Test.cs
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/* Tests for the wolfCrypt C# wrapper */

using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using wolfSSL.CSharp;
using System.Runtime.InteropServices;
using static wolfSSL.CSharp.wolfcrypt;

public class wolfCrypt_Test_CSharp
{
    private static void random_test()
    {
        int ret, i, zeroCount = 0;
        Byte[] data = new Byte[128];

        Console.WriteLine("Starting RNG test");

        /* Random Test */
        ret = wolfcrypt.Random(data, data.Length);
        if (ret == 0)
        {
            /* Check for 0's */
            for (i = 0; i < (int)data.Length; i++)
            {
                if (data[i] == 0)
                {
                    zeroCount++;
                }
            }
            if (zeroCount == data.Length)
            {
                Console.WriteLine("RNG zero check error");
            }
            else
            {
                Console.WriteLine("RNG Test Passed");
            }
        }
        else
        {
            Console.WriteLine("RNG Error" + wolfcrypt.GetError(ret));
        }
    } /* END random_test */

    private static void ecc_test(string hashAlgorithm, int keySize)
    {
        int ret;
        IntPtr rng = IntPtr.Zero;
        IntPtr PrivKey = IntPtr.Zero;
        IntPtr PubKey = IntPtr.Zero;
        IntPtr key = IntPtr.Zero;

        Console.WriteLine("\nStarting ECC" + (keySize*8) + " test for " + hashAlgorithm + "...");

        /* Create a new RNG context */
        rng = wolfcrypt.RandomNew();
        if (rng == IntPtr.Zero)
        {
            throw new Exception("RNG initialization failed.");
        }

        /* Generate ECC Key Pair */
        Console.WriteLine("Testing ECC Key Generation...");
        key = wolfcrypt.EccMakeKey(keySize, rng);
        if (key == IntPtr.Zero)
        {
            throw new Exception("EccMakeKey failed");
        }
        Console.WriteLine("ECC Key Generation test passed.");

        /* Export and Import Key */
        Console.WriteLine("Testing ECC Key Export and Import...");
        byte[] privateKeyDer;
        ret = wolfcrypt.EccExportPrivateKeyToDer(key, out privateKeyDer);
        if (ret < 0) {
            throw new Exception("ExportPrivateKeyToDer failed");
        }
        byte[] publicKeyDer;
        ret = wolfcrypt.EccExportPublicKeyToDer(key, out publicKeyDer, true);
        if (ret < 0) {
            throw new Exception("ExportPublicKeyToDer failed");
        }
        PrivKey = wolfcrypt.EccImportKey(privateKeyDer);
        if (PrivKey == IntPtr.Zero)
        {
            throw new Exception("EccImportKey Private failed");
        }

        PubKey = wolfcrypt.EccImportPublicKeyFromDer(publicKeyDer);
        if (PubKey == IntPtr.Zero)
        {
            throw new Exception("ImportPublicKeyFromDer Public failed");
        }
        Console.WriteLine("ECC Key Export and Import test passed.");

        /* Generate hash based on selected algorithm */
        byte[] dataToHash = System.Text.Encoding.UTF8.GetBytes("This is some data to hash");
        byte[] hash;

        switch (hashAlgorithm.ToUpper())
        {
            case "SHA256":
                using (SHA256 sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(dataToHash);
                }
                break;

            case "SHA384":
                using (SHA384 sha384 = SHA384.Create())
                {
                    hash = sha384.ComputeHash(dataToHash);
                }
                break;

            case "SHA512":
                using (SHA512 sha512 = SHA512.Create())
                {
                    hash = sha512.ComputeHash(dataToHash);
                }
                break;

            default:
                throw new Exception("Unsupported hash algorithm");
        }
        Console.WriteLine($"{hashAlgorithm} hash generated.");

        /* Sign Data */
        Console.WriteLine("Testing ECC Signature Creation...");
        byte[] signature = new byte[wolfcrypt.ECC_MAX_SIG_SIZE];
        int signLength = wolfcrypt.EccSign(PrivKey, hash, signature);
        if (signLength <= 0)
        {
            throw new Exception("EccSign failed");
        }

        byte[] actualSignature = new byte[signLength];
        Array.Copy(signature, 0, actualSignature, 0, signLength);

        Console.WriteLine($"ECC Signature Creation test passed. Signature Length: {signLength}");

        /* Verify Signature */
        Console.WriteLine("Testing ECC Signature Verification...");
        int verifyResult = wolfcrypt.EccVerify(PubKey, actualSignature, hash);
        if (verifyResult != 0)
        {
            throw new Exception("EccVerify failed");
        }
        Console.WriteLine("ECC Signature Verification test passed.");

        /* Cleanup */
        if (key != IntPtr.Zero) wolfcrypt.EccFreeKey(key);
        if (PubKey != IntPtr.Zero) wolfcrypt.EccFreeKey(PubKey);
        if (PrivKey != IntPtr.Zero) wolfcrypt.EccFreeKey(PrivKey);
        if (rng != IntPtr.Zero) wolfcrypt.RandomFree(rng);
    } /* END ecc_test */

    private static void ecies_test(int keySize)
    {
        /* maximum encrypted message:
         * msgSz (14) + pad (2) + pubKeySz(1+66*2) + ivSz(16) + digestSz(32) = 197 */
        int bufferSize = wolfcrypt.MAX_ECIES_TEST_SZ;
        const string message = "Hello wolfSSL!";
        byte[] salt = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

        IntPtr a = IntPtr.Zero;
        IntPtr b = IntPtr.Zero;
        IntPtr aCtx = IntPtr.Zero;
        IntPtr bCtx = IntPtr.Zero;
        IntPtr rng = IntPtr.Zero;
        IntPtr heap = IntPtr.Zero;

        byte[] plaintext = new byte[bufferSize];
        byte[] encrypted = new byte[bufferSize];
        byte[] decrypted = new byte[bufferSize];

        try
        {
            Console.WriteLine($"\nStarting ECIES test for {keySize} byte key size...");

            /* Create a new RNG context */
            rng = wolfcrypt.RandomNew();
            if (rng == IntPtr.Zero)
            {
                throw new Exception("RNG initialization failed.");
            }

            /* Initialize keys */
            a = wolfcrypt.EccMakeKey(keySize, rng);
            b = wolfcrypt.EccMakeKey(keySize, rng);
            if (a == IntPtr.Zero || b == IntPtr.Zero)
            {
                throw new Exception("Key generation failed.");
            }
            Console.WriteLine("ECC key generation passed.");

            /* Create ECIES contexts for encryption and decryption */
            aCtx = wolfcrypt.EciesNewCtx((int)wolfcrypt.ecFlags.REQ_RESP_CLIENT, rng, heap);
            bCtx = wolfcrypt.EciesNewCtx((int)wolfcrypt.ecFlags.REQ_RESP_SERVER, rng, heap);
            if (aCtx == IntPtr.Zero || bCtx == IntPtr.Zero)
            {
                throw new Exception("Context creation failed.");
            }
            Console.WriteLine("ECC context creation passed.");

            /* Set KDF salt */
            if (wolfcrypt.EciesSetKdfSalt(aCtx, salt) != 0 ||
                wolfcrypt.EciesSetKdfSalt(bCtx, salt) != 0)
            {
                throw new Exception("Failed to set KDF salt.");
            }
            Console.WriteLine("KDF salt setup passed.");

            /* Prepare plaintext */
            Array.Clear(plaintext, 0, plaintext.Length);
            Array.Copy(Encoding.ASCII.GetBytes(message), plaintext, message.Length);
            /* Pad to block size */
            int plaintextLen = ((message.Length + (wolfcrypt.AES_BLOCK_SIZE - 1)) /
                                wolfcrypt.AES_BLOCK_SIZE) * wolfcrypt.AES_BLOCK_SIZE;

            /* Encrypt message */
            int ret = wolfcrypt.EciesEncrypt(a, b, plaintext, (uint)plaintextLen, encrypted, aCtx);
            if (ret < 0)
            {
                throw new Exception("Encryption failed.");
            }

            int encryptedLen = ret;
            Console.WriteLine("ECC encryption passed.");

            /* Decrypt message */
            ret = wolfcrypt.EciesDecrypt(b, a, encrypted, (uint)encryptedLen, decrypted, bCtx);
            if (ret < 0)
            {
                throw new Exception("Decryption failed.");
            }

            int decryptedLen = ret;
            Console.WriteLine("ECC decryption passed.");

            /* Compare decrypted text to original plaintext */
            if (decryptedLen != plaintextLen || !wolfcrypt.ByteArrayVerify(plaintext, decrypted))
            {
                throw new Exception("Decrypted text does not match original plaintext.");
            }
            Console.WriteLine("Decrypted text matches original plaintext.");
        }
        finally
        {
            /* Cleanup key and context */
            if (a != IntPtr.Zero) wolfcrypt.EccFreeKey(a);
            if (b != IntPtr.Zero) wolfcrypt.EccFreeKey(b);
            if (aCtx != IntPtr.Zero) wolfcrypt.EciesFreeCtx(aCtx);
            if (bCtx != IntPtr.Zero) wolfcrypt.EciesFreeCtx(bCtx);
            if (rng != IntPtr.Zero) wolfcrypt.RandomFree(rng);
        }
    } /* END ecies_test */

    private static void ecdhe_test(int keySize)
    {
        int ret;
        IntPtr rng = IntPtr.Zero;
        IntPtr keyA = IntPtr.Zero;
        IntPtr keyB = IntPtr.Zero;
        IntPtr publicKeyA = IntPtr.Zero;
        IntPtr publicKeyB = IntPtr.Zero;
        byte[] derKey;

        Console.WriteLine("\nStarting ECDHE shared secret test for " + keySize + " key size...");

        /* Create RNG */
        Console.WriteLine("Generating RNG...");
        rng = RandomNew();
        if (rng == IntPtr.Zero)
        {
            throw new Exception("Failed to generate RNG.");
        }
        Console.WriteLine("RNG generation test passed.");

        /* Generate Key Pair A */
        Console.WriteLine("Generating Key Pair A...");
        keyA = wolfcrypt.EccMakeKey(keySize, rng);
        if (keyA == IntPtr.Zero)
        {
            throw new Exception("Failed to generate key pair A.");
        }

        /* Generate Key Pair B */
        Console.WriteLine("Generating Key Pair B...");
        keyB = wolfcrypt.EccMakeKey(keySize, rng);
        if (keyB == IntPtr.Zero)
        {
            throw new Exception("Failed to generate key pair B.");
        }
        Console.WriteLine("ECC Key generation test passed.");

        /* Export Public Key B to DER format */
        Console.WriteLine("Exporting Public Key B to DER format...");
        ret = wolfcrypt.EccExportPublicKeyToDer(keyB, out derKey, true);
        if (ret < 0 || derKey == null)
        {
            throw new Exception("EccExportPublicKeyToDer failed");
        }

        /* Decode Public Key B from DER format */
        Console.WriteLine("Decoding Public Key B from DER format...");
        publicKeyB = wolfcrypt.EccImportPublicKeyFromDer(derKey);
        if (publicKeyB == IntPtr.Zero)
        {
            throw new Exception("Failed to decode public key B from DER format.");
        }
        Console.WriteLine("ECC Export and Import test passed.");

        /* Compute Shared Secret using Private Key A and Public Key B */
        Console.WriteLine("Computing Shared Secret using Private Key A and Public Key B...");
        byte[] sharedSecretA = new byte[keySize];
        int retA = wolfcrypt.EcdheSharedSecret(keyA, publicKeyB, sharedSecretA, rng);
        if (retA != 0)
        {
            throw new Exception("Failed to compute shared secret A. Error code: " + retA);
        }
        Console.WriteLine("ECC shared secret created using private Key A.");

        /* Export Public Key A to DER format */
        Console.WriteLine("Exporting Public Key A to DER format...");
        ret = wolfcrypt.EccExportPublicKeyToDer(keyA, out derKey, true);
        if (ret < 0 || derKey == null)
        {
            throw new Exception("EccExportPublicKeyToDer failed");
        }

        /* Decode Public Key A from DER format */
        Console.WriteLine("Decoding Public Key A from DER format...");
        publicKeyA = wolfcrypt.EccImportPublicKeyFromDer(derKey);
        if (publicKeyA == IntPtr.Zero)
        {
            throw new Exception("Failed to decode public key A from DER format.");
        }

        /* Compute Shared Secret using Private Key B and Public Key A */
        Console.WriteLine("Computing Shared Secret using Private Key B and Public Key A...");
        byte[] sharedSecretB = new byte[keySize];
        int retB = wolfcrypt.EcdheSharedSecret(keyB, publicKeyA, sharedSecretB, rng);
        if (retB != 0)
        {
            throw new Exception("Failed to compute shared secret B. Error code: " + retB);
        }
        Console.WriteLine("ECC shared secret created using private Key B.");

        /* Compare Shared Secrets */
        Console.WriteLine("Comparing Shared Secrets...");
        if (!wolfcrypt.ByteArrayVerify(sharedSecretA, sharedSecretB))
        {
            throw new Exception("Shared secrets do not match.");
        }
        else
        {
            Console.WriteLine("ECC shared secret match.");
        }

        /* Cleanup */
        if (keyA != IntPtr.Zero) wolfcrypt.EccFreeKey(keyA);
        if (keyB != IntPtr.Zero) wolfcrypt.EccFreeKey(keyB);
        if (publicKeyA != IntPtr.Zero) wolfcrypt.EccFreeKey(publicKeyA);
        if (publicKeyB != IntPtr.Zero) wolfcrypt.EccFreeKey(publicKeyB);
        if (rng != IntPtr.Zero) wolfcrypt.RandomFree(rng);
    } /* END ecdhe_test */

    private static void rsa_test(string hashAlgorithm, int keySize)
    {
        IntPtr key = IntPtr.Zero;
        IntPtr heap = IntPtr.Zero;
        int devId = wolfcrypt.INVALID_DEVID;

        Console.WriteLine("\nStarting RSA" + keySize + " test for " + hashAlgorithm + "...");

        /* Generate RSA Key Pair */
        Console.WriteLine("Testing RSA Key Generation...");
        key = wolfcrypt.RsaMakeKey(heap, devId, keySize);
        if (key == IntPtr.Zero)
        {
            throw new Exception("RsaMakeKey failed");
        }
        Console.WriteLine("RSA Key Generation test passed.");

        /* Generate hash based on selected algorithm */
        byte[] dataToHash = System.Text.Encoding.UTF8.GetBytes("This is some data to hash");
        byte[] hash;

        switch (hashAlgorithm.ToUpper())
        {
            case "SHA256":
                using (SHA256 sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(dataToHash);
                }
                break;

            case "SHA384":
                using (SHA384 sha384 = SHA384.Create())
                {
                    hash = sha384.ComputeHash(dataToHash);
                }
                break;

            case "SHA512":
                using (SHA512 sha512 = SHA512.Create())
                {
                    hash = sha512.ComputeHash(dataToHash);
                }
                break;

            default:
                throw new Exception("Unsupported hash algorithm");
        }
        Console.WriteLine($"{hashAlgorithm} hash generated.");

        /* Sign Data */
        Console.WriteLine("Testing RSA Signature Creation...");
        byte[] signature = new byte[keySize / 8];
        int signLength = wolfcrypt.RsaSignSSL(key, hash, signature);
        if (signLength <= 0)
        {
            throw new Exception("RsaSignSSL failed");
        }

        byte[] actualSignature = new byte[signLength];
        Array.Copy(signature, 0, actualSignature, 0, signLength);

        Console.WriteLine($"RSA Signature Creation test passed. Signature Length: {signLength}");

        /* Verify Signature */
        Console.WriteLine("Testing RSA Signature Verification...");
        int verifyResult = wolfcrypt.RsaVerifySSL(key, actualSignature, hash);
        if (verifyResult != 0)
        {
            throw new Exception("RsaVerifySSL failed");
        }
        Console.WriteLine("RSA Signature Verification test passed.");

        /* Cleanup */
        if (key != IntPtr.Zero) wolfcrypt.RsaFreeKey(key);
    } /* END rsa_test */

    private static void ed25519_test()
    {
        int ret;
        IntPtr key = IntPtr.Zero;
        byte[] privKey;
        byte[] pubKey;

        Console.WriteLine("\nStarting ED25519 tests...");

        IntPtr heap = IntPtr.Zero;
        int devId = wolfcrypt.INVALID_DEVID;

        /* Generate ED25519 Key Pair */
        Console.WriteLine("Testing ED25519 Key Generation...");
        key = wolfcrypt.Ed25519MakeKey(heap, devId);
        if (key == IntPtr.Zero)
        {
            throw new Exception("Ed25519MakeKey failed");
        }
        Console.WriteLine("ED25519 Key Generation test passed.");

        /* Export and Import Key */
        Console.WriteLine("Testing ED25519 Key Export and Import...");
        /* Export Private */
        ret = wolfcrypt.Ed25519ExportKeyToDer(key, out privKey);
        if (ret < 0 || privKey == null)
        {
            throw new Exception("Ed25519ExportKeyToDer failed");
        }
        /* Export Public */
        ret = wolfcrypt.Ed25519ExportPublicKeyToDer(key, out pubKey, true);
        if (ret < 0 || pubKey == null)
        {
            throw new Exception("Ed25519ExportKeyToDer failed");
        }
        /* Import Private */
        IntPtr importedPrivKey = wolfcrypt.Ed25519PrivateKeyDecode(privKey);
        if (importedPrivKey == IntPtr.Zero)
        {
            throw new Exception("Ed25519PrivateKeyDecode failed");
        }
        /* Import Public */
        IntPtr importedPubKey = wolfcrypt.Ed25519PublicKeyDecode(pubKey);
        if (importedPubKey == IntPtr.Zero)
        {
            throw new Exception("Ed25519PublicKeyDecode failed");
        }
        Console.WriteLine("ED25519 Key Export and Import test passed.");

        /* Generate a hash */
        byte[] dataToHash = System.Text.Encoding.UTF8.GetBytes("This is some data to hash");

        /* Sign Data */
        Console.WriteLine("Testing ED25519 Signature Creation...");
        byte[] signature;

        ret = wolfcrypt.Ed25519SignMsg(dataToHash, out signature, key);
        if (ret != 0)
        {
            throw new Exception("Ed25519SignMsg failed");
        }
        Console.WriteLine($"ED25519 Signature Creation test passed. Signature Length: {signature.Length}");

        /* Verify Signature */
        Console.WriteLine("Testing ED25519 Signature Verification...");
        ret = wolfcrypt.Ed25519VerifyMsg(signature, dataToHash, key);
        if (ret != 0)
        {
            throw new Exception("Ed25519VerifyMsg failed");
        }
        Console.WriteLine("ED25519 Signature Verification test passed.");

        /* Cleanup */
        if (key != IntPtr.Zero) wolfcrypt.Ed25519FreeKey(key);
    } /* END ed25519_test */

    private static void curve25519_test()
    {
        int ret;
        IntPtr keyA = IntPtr.Zero;
        IntPtr keyB = IntPtr.Zero;
        IntPtr publicKeyA = IntPtr.Zero;
        IntPtr publicKeyB = IntPtr.Zero;
        byte[] derKey;

        Console.WriteLine("\nStarting Curve25519 shared secret test...");

        /* Generate Key Pair A */
        Console.WriteLine("Generating Key Pair A...");
        keyA = wolfcrypt.Curve25519MakeKey(IntPtr.Zero, 0);
        if (keyA == IntPtr.Zero)
        {
            throw new Exception("Failed to generate key pair A.");
        }

        /* Generate Key Pair B */
        Console.WriteLine("Generating Key Pair B...");
        keyB = wolfcrypt.Curve25519MakeKey(IntPtr.Zero, 0);
        if (keyB == IntPtr.Zero)
        {
            throw new Exception("Failed to generate key pair B.");
        }
        Console.WriteLine("Curve25519 Key generation test passed.");

        /* Export Public Key B to DER format */
        Console.WriteLine("Exporting Public Key B to DER format...");
        ret = wolfcrypt.Curve25519ExportPublicKeyToDer(keyB, out derKey, true);
        if (ret < 0 || derKey == null)
        {
            throw new Exception("Curve25519ExportPublicKeyToDer failed");
        }

        /* Decode Public Key B from DER format */
        Console.WriteLine("Decoding Public Key B from DER format...");
        publicKeyB = wolfcrypt.Curve25519PublicKeyDecode(derKey);
        if (publicKeyB == IntPtr.Zero)
        {
            throw new Exception("Failed to decode public key B from DER format.");
        }
        Console.WriteLine("Curve25519 Export and Import test passed.");

        /* Compute Shared Secret using Private Key A and Public Key B */
        Console.WriteLine("Computing Shared Secret using Private Key A and Public Key B...");
        byte[] sharedSecretA = new byte[wolfcrypt.ED25519_KEY_SIZE];
        int retA = wolfcrypt.Curve25519SharedSecret(keyA, publicKeyB, sharedSecretA);
        if (retA != 0)
        {
            throw new Exception("Failed to compute shared secret A. Error code: " + retA);
        }
        Console.WriteLine("Curve25519 shared secret created using private Key A.");

        /* Export Public Key A to DER format */
        Console.WriteLine("Exporting Public Key A to DER format...");
        ret = wolfcrypt.Curve25519ExportPublicKeyToDer(keyA, out derKey, true);
        if (ret < 0 || derKey == null)
        {
            throw new Exception("Curve25519ExportPublicKeyToDer failed");
        }

        /* Decode Public Key A from DER format */
        Console.WriteLine("Decoding Public Key A from DER format...");
        publicKeyA = wolfcrypt.Curve25519PublicKeyDecode(derKey);
        if (publicKeyA == IntPtr.Zero)
        {
            throw new Exception("Failed to decode public key A from DER format.");
        }

        /* Compute Shared Secret using Private Key B and Public Key A */
        Console.WriteLine("Computing Shared Secret using Private Key B and Public Key A...");
        byte[] sharedSecretB = new byte[wolfcrypt.ED25519_KEY_SIZE];
        int retB = wolfcrypt.Curve25519SharedSecret(keyB, publicKeyA, sharedSecretB);
        if (retB != 0)
        {
            throw new Exception("Failed to compute shared secret B. Error code: " + retB);
        }
        Console.WriteLine("Curve25519 shared secret created using private Key B.");

        /* Compare Shared Secrets */
        Console.WriteLine("Comparing Shared Secrets...");
        if (!wolfcrypt.ByteArrayVerify(sharedSecretA, sharedSecretB))
        {
            throw new Exception("Shared secrets do not match.");
        }
        else
        {
            Console.WriteLine("Curve25519 shared secret match.");
        }

        /* Cleanup */
        if (keyA != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(keyA);
        if (keyB != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(keyB);
        if (publicKeyA != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(publicKeyA);
        if (publicKeyB != IntPtr.Zero) wolfcrypt.Curve25519FreeKey(publicKeyB);
    } /* END curve25519_test */

    private static void aes_gcm_test()
    {
        IntPtr aes = IntPtr.Zero;
        byte[] key;
        byte[] iv;
        byte[] plaintext;
        byte[] ciphertext;
        byte[] addAuth;
        byte[] authTag;
        byte[] decrypted;
        int ret;

        try
        {
            Console.WriteLine("\nStarting AES-GCM tests...");

            IntPtr heap = IntPtr.Zero;
            int devId = wolfcrypt.INVALID_DEVID;

            /* Initialize AES-GCM Context */
            Console.WriteLine("Testing AES-GCM Initialization...");

            /*
             * This is from the Test Case 16 from the document Galois/
             * Counter Mode of Operation (GCM) by McGrew and
             * Viega.
             */

            key = new byte[32]
            {
                0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
            };

            iv = new byte[12]
            {
                0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
                0xde, 0xca, 0xf8, 0x88
            };

            plaintext = new byte[]
            {
                0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
                0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
                0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
                0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
                0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
                0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
                0xba, 0x63, 0x7b, 0x39
            };


            ciphertext = new byte[]
            {
                0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
                0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
                0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
                0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
                0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
                0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
                0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
                0xbc, 0xc9, 0xf6, 0x62
            };

            addAuth = new byte[]
            {
                0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                0xab, 0xad, 0xda, 0xd2
            };

            authTag = new byte[16];

            aes = wolfcrypt.AesNew(heap, devId);
            if (aes == IntPtr.Zero)
            {
                throw new Exception($"AesNew failed with error code {aes}");
            }
            Console.WriteLine("AesNew test passed.");

            /* Set AES-GCM Key */
            Console.WriteLine("Testing AES-GCM Key Setting...");
            uint len = (uint)key.Length;
            ret = wolfcrypt.AesGcmSetKey(aes, key);
            if (ret != 0)
            {
                throw new Exception($"AesGcmSetKey failed with error code {ret}");
            }
            Console.WriteLine("AES-GCM Key Setting test passed.");

            /* Encryption */
            Console.WriteLine("Testing AES-GCM Encryption...");
            ret = wolfcrypt.AesGcmEncrypt(aes, iv, plaintext, ciphertext, authTag, addAuth);
            if (ret != 0)
            {
                throw new Exception($"AesGcmEncrypt failed with error code {ret}");
            }
            Console.WriteLine($"AES-GCM Encryption test passed. Ciphertext Length: {ciphertext.Length}");

            /* Decryption */
            Console.WriteLine("Testing AES-GCM Decryption...");
            decrypted = new byte[plaintext.Length];

            ret = wolfcrypt.AesGcmDecrypt(aes, iv, ciphertext, decrypted, authTag, addAuth);
            if (ret != 0)
            {
                throw new Exception($"AesGcmDecrypt failed with error code {ret}");
            }

            /* Verify Decryption */
            if (!plaintext.SequenceEqual(decrypted))
            {
                throw new Exception("Decryption failed: decrypted data does not match original plaintext.");
            }
            Console.WriteLine("AES-GCM Decryption test passed.");

        }
        catch (Exception ex)
        {
            Console.WriteLine($"AES-GCM test failed: {ex.Message}");
        }
        finally
        {
            /* Cleanup */
            if (aes != IntPtr.Zero)
            {
                wolfcrypt.AesGcmFree(aes);
            }
        }
    } /* END aes_gcm_test */

    private static void hash_test(uint hashType)
    {
        IntPtr hash = IntPtr.Zero;
        IntPtr heap = IntPtr.Zero;
        int devId = wolfcrypt.INVALID_DEVID;

        /* Get the enum name */
        string hashTypeName = Enum.GetName(typeof(wolfcrypt.hashType), hashType);

        Console.WriteLine($"\nStarting hash test for {hashTypeName}...");

        /* Allocate new hash context */
        Console.WriteLine("Testing hash context allocation...");
        hash = wolfcrypt.HashNew(hashType, heap, devId);
        if (hash == IntPtr.Zero)
        {
            Console.WriteLine($"HashNew failed for {hashTypeName}");
            return;
        }
        Console.WriteLine("Hash context allocation test passed.");

        /* Initialize the hash context with the specified hash type */
        Console.WriteLine("Testing hash initialization...");
        int initResult = wolfcrypt.InitHash(hash, hashType);
        if (initResult != 0)
        {
            Console.WriteLine($"InitHash failed for {hashTypeName}");
            wolfcrypt.HashFree(hash, hashType);
            return;
        }
        Console.WriteLine("Hash initialization test passed.");

        /* Update the hash with data */
        byte[] dataToHash = Encoding.UTF8.GetBytes("This is some data to hash");
        Console.WriteLine("Testing hash update...");
        int updateResult = wolfcrypt.HashUpdate(hash, hashType, dataToHash);
        if (updateResult != 0)
        {
            Console.WriteLine($"HashUpdate failed for {hashTypeName}");
            wolfcrypt.HashFree(hash, hashType);
            return;
        }
        Console.WriteLine("Hash update test passed.");

        /* Finalize the hash and get the result */
        Console.WriteLine("Testing hash finalization...");
        byte[] hashOutput;
        int finalResult = wolfcrypt.HashFinal(hash, hashType, out hashOutput);
        if (finalResult != 0)
        {
            Console.WriteLine($"HashFinal failed for {hashType}");
            wolfcrypt.HashFree(hash, hashType);
            return;
        }
        Console.WriteLine($"Hash finalization test passed for {hashTypeName}. Hash Length: {hashOutput.Length}");

        /* Output the hash result */
        Console.WriteLine($"Hash Output ({hashTypeName}): {BitConverter.ToString(hashOutput).Replace("-", "")}");

        /* Cleanup */
        Console.WriteLine("Testing hash cleanup...");
        int freeResult = wolfcrypt.HashFree(hash, hashType);
        if (freeResult != 0)
        {
            Console.WriteLine($"HashFree failed for {hashTypeName}");
        }
        else
        {
            Console.WriteLine("Hash cleanup test passed.");
        }
    } /* END hash_test */

    public static void standard_log(int lvl, StringBuilder msg)
    {
        Console.WriteLine(msg);
    }

    public static void Main(string[] args)
    {
        try
        {
            Console.WriteLine("Starting Cryptographic Tests...\n");

            wolfcrypt.Init();

            /* setup logging to stdout */
            wolfcrypt.SetLogging(standard_log);

            random_test();

            Console.WriteLine("\nStarting ECC tests");

            ecc_test("SHA256", 32); /* Uses SHA-256 (32 byte hash) */
            ecc_test("SHA384", 32); /* Uses SHA-384 (32 byte hash) */
            ecc_test("SHA512", 32); /* Uses SHA-512 (32 byte hash) */

            Console.WriteLine("\nStarting ECIES tests");

            ecies_test(32); /* ECIES test (32 byte key size) */
            ecies_test(48); /* ECIES test (48 byte key size) */
            ecies_test(66); /* ECIES test (66 byte key size) */

            Console.WriteLine("\nStarting ECDHE tests");

            ecdhe_test(32); /* ECDHE shared secret test (32 byte key size) */
            ecdhe_test(48); /* ECDHE shared secret test (48 byte key size) */
            ecdhe_test(66); /* ECDHE shared secret test (66 byte key size) */

            Console.WriteLine("\nStarting RSA tests");

            rsa_test("SHA256", 2048); /* Uses SHA-256 (2048 bit hash) */
            rsa_test("SHA384", 2048); /* Uses SHA-384 (2048 bit hash) */
            rsa_test("SHA512", 2048); /* Uses SHA-512 (2048 bit hash) */

            Console.WriteLine("\nStarting ED25519 test");

            ed25519_test(); /* ED25519 test */

            Console.WriteLine("\nStarting curve25519 test");

            curve25519_test(); /* curve25519 shared secret test */

            Console.WriteLine("\nStarting AES-GCM test");

            aes_gcm_test(); /* AES_GCM test */

            Console.WriteLine("\nStarting HASH tests");

            hash_test((uint)wolfcrypt.hashType.WC_HASH_TYPE_SHA256); /* SHA-256 HASH test */
            hash_test((uint)wolfcrypt.hashType.WC_HASH_TYPE_SHA384); /* SHA-384 HASH test */
            hash_test((uint)wolfcrypt.hashType.WC_HASH_TYPE_SHA512); /* SHA-512 HASH test */
            hash_test((uint)wolfcrypt.hashType.WC_HASH_TYPE_SHA3_256); /* SHA3_256 HASH test */

            wolfcrypt.Cleanup();

            Console.WriteLine("\nAll tests completed successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
            Environment.Exit(-1);
        }
    }
}
