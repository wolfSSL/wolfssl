/* FipsError.cs
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
    /* FIPS-related error codes returned by wolfCrypt FIPS v5.2.3.
     * Values copied from wolfssl/wolfcrypt/error-crypt.h of the v5.2.3
     * module; only codes that the v5.2.3 module can produce are listed. */
    public static class FipsError
    {
        public const int SUCCESS                   = 0;
        public const int BAD_FUNC_ARG              = -173;
        public const int AES_GCM_AUTH_E            = -180;
        public const int AES_CCM_AUTH_E            = -181;
        public const int BAD_LENGTH_E              = -279;
        public const int FIPS_DEGRADED_E           = -127;
        public const int FIPS_CODE_SZ_E            = -128;
        public const int FIPS_DATA_SZ_E            = -129;
        public const int FIPS_NOT_ALLOWED_E        = -197;
        public const int HMAC_MIN_KEYLEN_E         = -200;
        public const int IN_CORE_FIPS_E            = -203;
        public const int AES_KAT_FIPS_E            = -204;
        public const int DES3_KAT_FIPS_E           = -205;
        public const int HMAC_KAT_FIPS_E           = -206;
        public const int RSA_KAT_FIPS_E            = -207;
        public const int DRBG_KAT_FIPS_E           = -208;
        public const int DRBG_CONT_FIPS_E          = -209;
        public const int AESGCM_KAT_FIPS_E         = -210;
        public const int FIPS_INVALID_VER_E        = -233;
        public const int ECC_CDH_KAT_FIPS_E        = -242;
        public const int RSAPSS_PAT_FIPS_E         = -254;
        public const int ECDSA_PAT_FIPS_E          = -255;
        public const int DH_KAT_FIPS_E             = -256;
        public const int AESCCM_KAT_FIPS_E         = -257;
        public const int SHA3_KAT_FIPS_E           = -258;
        public const int ECDHE_KAT_FIPS_E          = -259;
        public const int ECDSA_KAT_FIPS_E          = -280;
        public const int RSA_PAT_FIPS_E            = -281;
        public const int KDF_TLS12_KAT_FIPS_E      = -282;
        public const int KDF_TLS13_KAT_FIPS_E      = -283;
        public const int KDF_SSH_KAT_FIPS_E        = -284;
        public const int DHE_PCT_E                 = -285;
        public const int ECC_PCT_E                 = -286;
        public const int FIPS_PRIVATE_KEY_LOCKED_E = -287;

        /* True for errors that report the module's state (failed, degraded,
         * or a self-test failure) rather than a bad input. Verification
         * APIs throw on these instead of returning false, so a degraded
         * module is never mistaken for an invalid signature or tag. */
        public static bool IsModuleStateError(int code) =>
            code == FIPS_NOT_ALLOWED_E || code == FIPS_DEGRADED_E || code == IN_CORE_FIPS_E ||
            code == AES_KAT_FIPS_E || code == DES3_KAT_FIPS_E || code == HMAC_KAT_FIPS_E ||
            code == RSA_KAT_FIPS_E || code == DRBG_KAT_FIPS_E || code == DRBG_CONT_FIPS_E ||
            code == AESGCM_KAT_FIPS_E || code == ECC_CDH_KAT_FIPS_E || code == RSAPSS_PAT_FIPS_E ||
            code == ECDSA_PAT_FIPS_E || code == DH_KAT_FIPS_E || code == AESCCM_KAT_FIPS_E ||
            code == SHA3_KAT_FIPS_E || code == ECDHE_KAT_FIPS_E || code == ECDSA_KAT_FIPS_E ||
            code == RSA_PAT_FIPS_E || code == KDF_TLS12_KAT_FIPS_E || code == KDF_TLS13_KAT_FIPS_E ||
            code == KDF_SSH_KAT_FIPS_E || code == DHE_PCT_E || code == ECC_PCT_E;

        public static string Name(int code)
        {
            foreach (var f in typeof(FipsError).GetFields())
                if (f.IsLiteral && (int)f.GetRawConstantValue()! == code)
                    return f.Name;
            return "UNKNOWN(" + code + ")";
        }
    }

    /* Thrown when a wolfCrypt FIPS call returns an error. Code holds the
     * native return value (see FipsError). */
    public class WolfCryptFipsException : Exception
    {
        public int Code { get; }

        public WolfCryptFipsException(string function, int code)
            : base(function + " failed: " + FipsError.Name(code) + " (" + code + ")")
        {
            Code = code;
        }

        internal static void Check(string function, int ret)
        {
            if (ret != 0)
                throw new WolfCryptFipsException(function, ret);
        }
    }
}
