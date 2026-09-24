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
    /* Error codes returned by wolfCrypt FIPS v5.2.3: the FIPS state and
     * self-test codes, plus the common argument, math and algorithm codes
     * the bound services return. Values copied from
     * wolfssl/wolfcrypt/error-crypt.h of the v5.2.x module. */
    public static class FipsError
    {
        public const int SUCCESS                   = 0;
        public const int BAD_FUNC_ARG              = -173;
        public const int AES_GCM_AUTH_E            = -180;
        public const int AES_CCM_AUTH_E            = -181;
        public const int BAD_LENGTH_E              = -279;
        public const int PRIME_GEN_E               = -251;
        public const int RSA_BUFFER_E              = -131;   /* also RSA padding failure */
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

        /* common non-FIPS codes */
        public const int MP_VAL                    = -98;
        public const int MP_READ_E                 = -111;
        public const int MP_EXPTMOD_E              = -112;
        public const int MP_INVMOD_E               = -119;
        public const int MP_CMP_E                  = -120;
        public const int MP_ZERO_E                 = -121;
        public const int MEMORY_E                  = -125;
        public const int BUFFER_E                  = -132;
        public const int PUBLIC_KEY_E              = -134;
        public const int ASN_PARSE_E               = -140;
        public const int ECC_BAD_ARG_E             = -170;
        public const int NOT_COMPILED_IN           = -174;
        public const int BAD_STATE_E               = -192;
        public const int BAD_PADDING_E             = -193;
        public const int RNG_FAILURE_E             = -199;
        public const int RSA_PAD_E                 = -201;
        public const int IS_POINT_E                = -214;
        public const int ECC_INF_E                 = -215;
        public const int ECC_PRIV_KEY_E            = -216;
        public const int ECC_OUT_OF_RANGE_E        = -217;
        public const int SIG_VERIFY_E              = -229;
        public const int HASH_TYPE_E               = -232;
        public const int WC_KEY_SIZE_E             = -234;
        public const int MISSING_RNG_E             = -236;
        public const int DH_CHECK_PUB_E            = -243;
        public const int ECC_PRIVATEONLY_E         = -246;
        public const int RSA_OUT_OF_RANGE_E        = -253;
        public const int RSA_KEY_PAIR_E            = -262;
        public const int DH_CHECK_PRIV_E           = -263;
        public const int MISSING_KEY               = -278;

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
