/* esp32_ecc.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>

#if defined(WOLFSSL_ESP32_CRYPT_ECC) || \
    defined(WOLFSSL_ESP32_CRYPT_ECDSA)

#include <wolfssl/wolfcrypt/port/Espressif/esp32-ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <esp_crypto_lock.h>
#include <esp_crypto_periph_clk.h>
#include <hal/ecc_hal.h>
#include <hal/ecdsa_hal.h>
#include <hal/ecdsa_ll.h>
#if defined(SOC_KEY_MANAGER_ECDSA_KEY_DEPLOY)
    #include <hal/key_mgr_hal.h>
#endif

#define ESP32_ECC_MAX_SIZE       48
#define ESP32_ECC_TIMEOUT_COUNT  0x1000000

#if defined(WOLFSSL_HW_METRICS)
static unsigned long esp32_ecc_mul_usage_ct = 0;
static unsigned long esp32_ecdsa_verify_usage_ct = 0;
#endif

static void esp32_ecc_reverse(byte* buf, word32 len)
{
    word32 i;

    for (i = 0; i < len / 2; i++) {
        byte tmp = buf[i];
        buf[i] = buf[len - i - 1];
        buf[len - i - 1] = tmp;
    }
}

static int esp32_ecc_export_le(const mp_int* value, byte* out, word32 len)
{
    int ret;
    int size = mp_unsigned_bin_size(value);

    if (size < 0 || (word32)size > len) {
        return ECC_OUT_OF_RANGE_E;
    }

    XMEMSET(out, 0, len);
    ret = mp_to_unsigned_bin(value, out + len - (word32)size);
    if (ret == MP_OKAY) {
        esp32_ecc_reverse(out, len);
    }
    return ret;
}

static int esp32_ecc_import_le(mp_int* value, byte* in, word32 len)
{
    esp32_ecc_reverse(in, len);
    return mp_read_unsigned_bin(value, in, len);
}

static int esp32_ecc_find_curve(mp_int* a, mp_int* modulus,
    ecc_curve_t* hwCurve, word32* curveSize)
{
    mp_int prime;
    mp_int aCurve;
    mp_int aMod;
    int ret;
    int idx;
    int found = 0;

    if (a == NULL || hwCurve == NULL || curveSize == NULL) {
        return NOT_COMPILED_IN;
    }

    ret = mp_init(&prime);
    if (ret != MP_OKAY) {
        return ret;
    }
    ret = mp_init(&aCurve);
    if (ret != MP_OKAY) {
        mp_clear(&prime);
        return ret;
    }
    ret = mp_init(&aMod);
    if (ret != MP_OKAY) {
        mp_clear(&aCurve);
        mp_clear(&prime);
        return ret;
    }

    ret = mp_mod(a, modulus, &aMod);
    for (idx = 0; ret == MP_OKAY && ecc_sets[idx].size != 0; idx++) {
        if (ecc_sets[idx].id != ECC_SECP192R1 &&
            ecc_sets[idx].id != ECC_SECP256R1 &&
            ecc_sets[idx].id != ECC_SECP384R1) {
            continue;
        }

        ret = mp_read_radix(&prime, ecc_sets[idx].prime, MP_RADIX_HEX);
        if (ret == MP_OKAY && mp_cmp(modulus, &prime) == MP_EQ) {
            ret = mp_read_radix(&aCurve, ecc_sets[idx].Af, MP_RADIX_HEX);
        }
        else {
            continue;
        }

        if (ret == MP_OKAY && mp_cmp(&aMod, &aCurve) == MP_EQ) {
            found = 1;
            *curveSize = (word32)ecc_sets[idx].size;
            if (ecc_sets[idx].id == ECC_SECP192R1) {
                *hwCurve = ECC_CURVE_SECP192R1;
            }
            else if (ecc_sets[idx].id == ECC_SECP256R1) {
                *hwCurve = ECC_CURVE_SECP256R1;
            }
            else {
                *hwCurve = ECC_CURVE_SECP384R1;
            }
            break;
        }
    }

    mp_clear(&aMod);
    mp_clear(&aCurve);
    mp_clear(&prime);

    if (ret != MP_OKAY) {
        return ret;
    }
    return found ? MP_OKAY : NOT_COMPILED_IN;
}

static int esp32_ecc_hw_point_mul(const byte* scalar, const byte* x,
    const byte* y, byte* outX, byte* outY, word32 len)
{
    word32 timeout = ESP32_ECC_TIMEOUT_COUNT;
    int ret;

    esp_crypto_ecc_lock_acquire();
    esp_crypto_ecc_enable_periph_clk(true);
#if defined(WOLFSSL_HW_METRICS)
    esp32_ecc_mul_usage_ct++;
#endif

    ecc_hal_write_mul_param(scalar, x, y, (uint16_t)len);
    ecc_hal_set_mode(ECC_MODE_VERIFY_THEN_POINT_MUL);
    ecc_hal_enable_constant_time_point_mul(true);
    ecc_hal_start_calc();

    while (!ecc_hal_is_calc_finished() && timeout > 0) {
        timeout--;
    }

    if (timeout == 0) {
        ret = WC_HW_WAIT_E;
    }
    else {
        ret = ecc_hal_read_mul_result(outX, outY, (uint16_t)len);
        if (ret != 0) {
            ret = IS_POINT_E;
        }
    }

    esp_crypto_ecc_enable_periph_clk(false);
    esp_crypto_ecc_lock_release();
    return ret;
}

static int esp32_ecc_hw_point_verify(const byte* x, const byte* y,
    word32 len)
{
    word32 timeout = ESP32_ECC_TIMEOUT_COUNT;
    int ret;

    esp_crypto_ecc_lock_acquire();
    esp_crypto_ecc_enable_periph_clk(true);

    ecc_hal_write_verify_param(x, y, (uint16_t)len);
    ecc_hal_set_mode(ECC_MODE_VERIFY);
    ecc_hal_start_calc();

    while (!ecc_hal_is_calc_finished() && timeout > 0) {
        timeout--;
    }

    if (timeout == 0) {
        ret = WC_HW_WAIT_E;
    }
    else if (ecc_hal_read_verify_result() != 1) {
        ret = IS_POINT_E;
    }
    else {
        ret = MP_OKAY;
    }

    esp_crypto_ecc_enable_periph_clk(false);
    esp_crypto_ecc_lock_release();
    return ret;
}

static void esp32_ecdsa_acquire(void)
{
    esp_crypto_ecdsa_lock_acquire();
    esp_crypto_ecdsa_enable_periph_clk(true);
    esp_crypto_ecc_enable_periph_clk(true);
#if defined(SOC_KEY_MANAGER_ECDSA_KEY_DEPLOY)
    esp_crypto_key_mgr_enable_periph_clk(true);
#endif
#if defined(SOC_ECDSA_USES_MPI) && SOC_ECDSA_USES_MPI
    if (ecdsa_ll_is_mpi_required()) {
        esp_crypto_mpi_enable_periph_clk(true);
    }
#endif
}

static void esp32_ecdsa_release(void)
{
    esp_crypto_ecdsa_enable_periph_clk(false);
    esp_crypto_ecc_enable_periph_clk(false);
#if defined(SOC_KEY_MANAGER_ECDSA_KEY_DEPLOY)
    esp_crypto_key_mgr_enable_periph_clk(false);
#endif
#if defined(SOC_KEY_MANAGER_SUPPORTED)
    esp_crypto_key_manager_lock_release();
#endif
#if defined(SOC_ECDSA_USES_MPI) && SOC_ECDSA_USES_MPI
    if (ecdsa_ll_is_mpi_required()) {
        esp_crypto_mpi_enable_periph_clk(false);
    }
#endif
    esp_crypto_ecdsa_lock_release();
}

static int esp32_ecdsa_hw_verify(ecdsa_curve_t curve, const byte* hash,
    const byte* r, const byte* s, const byte* qx, const byte* qy,
    word32 len)
{
    word32 timeout;
    int ret = MP_OKAY;
    int valid = 0;

#if defined(SOC_KEY_MANAGER_SUPPORTED)
    esp_crypto_key_manager_lock_acquire();
#endif
    esp32_ecdsa_acquire();
#if defined(WOLFSSL_HW_METRICS)
    esp32_ecdsa_verify_usage_ct++;
#endif

#if defined(SOC_KEY_MANAGER_ECDSA_KEY_DEPLOY)
    key_mgr_hal_set_key_usage(ESP_KEY_MGR_ECDSA_KEY,
        ESP_KEY_MGR_USE_EFUSE_KEY);
#endif
    ecdsa_hal_set_efuse_key(curve, 0);
    ecdsa_ll_set_mode(ECDSA_MODE_SIGN_VERIFY);
    ecdsa_ll_set_curve(curve);
    ecdsa_ll_set_z_mode(ECDSA_Z_USER_PROVIDED);
    ecdsa_ll_set_stage(ECDSA_STAGE_START_CALC);

    timeout = ESP32_ECC_TIMEOUT_COUNT;
    while (ecdsa_ll_get_state() != ECDSA_STATE_LOAD && timeout > 0) {
        timeout--;
    }
    if (timeout == 0) {
        ret = WC_HW_WAIT_E;
    }

    if (ret == MP_OKAY) {
        ecdsa_ll_write_param(ECDSA_PARAM_Z, hash, (uint16_t)len);
        ecdsa_ll_write_param(ECDSA_PARAM_R, r, (uint16_t)len);
        ecdsa_ll_write_param(ECDSA_PARAM_S, s, (uint16_t)len);
        ecdsa_ll_write_param(ECDSA_PARAM_QAX, qx, (uint16_t)len);
        ecdsa_ll_write_param(ECDSA_PARAM_QAY, qy, (uint16_t)len);
        ecdsa_ll_set_stage(ECDSA_STAGE_LOAD_DONE);
    }

    timeout = ESP32_ECC_TIMEOUT_COUNT;
    while (ret == MP_OKAY && ecdsa_ll_get_state() != ECDSA_STATE_IDLE &&
        timeout > 0) {
        timeout--;
    }
    if (ret == MP_OKAY && timeout == 0) {
        ret = WC_HW_WAIT_E;
    }
    if (ret == MP_OKAY) {
        valid = ecdsa_ll_get_operation_result();
    }

    esp32_ecdsa_release();
    return valid ? 1 : ret;
}

int esp32_ecdsa_verify_hash(mp_int* r, mp_int* s, const byte* hash,
    word32 hashLen, int* res, ecc_key* key)
{
    byte hashLe[ESP32_ECC_MAX_SIZE];
    byte rLe[ESP32_ECC_MAX_SIZE];
    byte sLe[ESP32_ECC_MAX_SIZE];
    byte qx[ESP32_ECC_MAX_SIZE];
    byte qy[ESP32_ECC_MAX_SIZE];
    ecdsa_curve_t curve;
    mp_int prime;
    word32 keySize;
    int ret;
    int hwRet;

    if (r == NULL || s == NULL || hash == NULL || res == NULL ||
        key == NULL || key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }
    if (key->idx == ECC_CUSTOM_IDX) {
        return NOT_COMPILED_IN;
    }

    keySize = (word32)key->dp->size;
    if (key->dp->id == ECC_SECP192R1) {
        curve = ECDSA_CURVE_SECP192R1;
        if (hashLen != 32) {
            return NOT_COMPILED_IN;
        }
    }
    else if (key->dp->id == ECC_SECP256R1) {
        curve = ECDSA_CURVE_SECP256R1;
        if (hashLen != 32) {
            return NOT_COMPILED_IN;
        }
    }
    else if (key->dp->id == ECC_SECP384R1) {
        curve = ECDSA_CURVE_SECP384R1;
        if (hashLen != 48) {
            return NOT_COMPILED_IN;
        }
    }
    else {
        return NOT_COMPILED_IN;
    }

    if (mp_cmp_d(key->pubkey.z, 1) != MP_EQ ||
        (mp_iszero(key->pubkey.x) && mp_iszero(key->pubkey.y))) {
        return NOT_COMPILED_IN;
    }

    ret = mp_init(&prime);
    if (ret != MP_OKAY) {
        return ret;
    }
    ret = mp_read_radix(&prime, key->dp->prime, MP_RADIX_HEX);
    if (ret == MP_OKAY && (mp_isneg(key->pubkey.x) ||
        mp_isneg(key->pubkey.y) || mp_cmp(key->pubkey.x, &prime) != MP_LT ||
        mp_cmp(key->pubkey.y, &prime) != MP_LT)) {
        ret = IS_POINT_E;
    }
    mp_clear(&prime);
    if (ret != MP_OKAY) {
        return ret;
    }

    XMEMSET(hashLe, 0, sizeof(hashLe));
    XMEMSET(rLe, 0, sizeof(rLe));
    XMEMSET(sLe, 0, sizeof(sLe));
    XMEMSET(qx, 0, sizeof(qx));
    XMEMSET(qy, 0, sizeof(qy));
    XMEMCPY(hashLe, hash, keySize);
    esp32_ecc_reverse(hashLe, keySize);

    ret = esp32_ecc_export_le(r, rLe, keySize);
    if (ret == MP_OKAY) {
        ret = esp32_ecc_export_le(s, sLe, keySize);
    }
    if (ret == MP_OKAY) {
        ret = esp32_ecc_export_le(key->pubkey.x, qx, keySize);
    }
    if (ret == MP_OKAY) {
        ret = esp32_ecc_export_le(key->pubkey.y, qy, keySize);
    }
    if (ret == MP_OKAY) {
        ret = esp32_ecc_hw_point_verify(qx, qy, keySize);
    }
    if (ret != MP_OKAY) {
        return ret;
    }

    hwRet = esp32_ecdsa_hw_verify(curve, hashLe, rLe, sLe, qx, qy, keySize);
    ForceZero(hashLe, sizeof(hashLe));
    ForceZero(rLe, sizeof(rLe));
    ForceZero(sLe, sizeof(sLe));
    if (hwRet < 0) {
        return hwRet;
    }

    *res = hwRet;
    return MP_OKAY;
}

int esp32_ecc_mulmod(const mp_int* k, ecc_point* G, ecc_point* R,
    mp_int* a, mp_int* modulus, int map, void* heap)
{
    byte scalar[ESP32_ECC_MAX_SIZE];
    byte x[ESP32_ECC_MAX_SIZE];
    byte y[ESP32_ECC_MAX_SIZE];
    ecc_curve_t hwCurve;
    word32 curveSize = 0;
    int ret;

    (void)heap;

    if (k == NULL || G == NULL || R == NULL || modulus == NULL) {
        return ECC_BAD_ARG_E;
    }
    if (mp_iszero(k)) {
        ret = mp_set(R->x, 0);
        if (ret == MP_OKAY) {
            ret = mp_set(R->y, 0);
        }
        if (ret == MP_OKAY) {
            ret = mp_set(R->z, 1);
        }
        return ret;
    }

    ret = esp32_ecc_find_curve(a, modulus, &hwCurve, &curveSize);
    if (ret != MP_OKAY) {
        return ret;
    }
    if (mp_isneg(k) || mp_count_bits(k) > (int)(curveSize * 8) ||
        mp_cmp_d(G->z, 1) != MP_EQ || mp_isneg(G->x) || mp_isneg(G->y) ||
        mp_cmp(G->x, modulus) != MP_LT || mp_cmp(G->y, modulus) != MP_LT) {
        return NOT_COMPILED_IN;
    }

    (void)hwCurve;
    XMEMSET(x, 0, sizeof(x));
    XMEMSET(y, 0, sizeof(y));
    ret = esp32_ecc_export_le(k, scalar, curveSize);
    if (ret == MP_OKAY) {
        ret = esp32_ecc_export_le(G->x, x, curveSize);
    }
    if (ret == MP_OKAY) {
        ret = esp32_ecc_export_le(G->y, y, curveSize);
    }
    if (ret == MP_OKAY) {
        ret = esp32_ecc_hw_point_mul(scalar, x, y, x, y, curveSize);
    }
    ForceZero(scalar, sizeof(scalar));
    if (ret != MP_OKAY) {
        ForceZero(x, sizeof(x));
        ForceZero(y, sizeof(y));
        return ret;
    }

    ret = esp32_ecc_import_le(R->x, x, curveSize);
    if (ret == MP_OKAY) {
        ret = esp32_ecc_import_le(R->y, y, curveSize);
    }
    ForceZero(x, sizeof(x));
    ForceZero(y, sizeof(y));
    if (ret != MP_OKAY) {
        return ret;
    }

    if (mp_iszero(R->x) && mp_iszero(R->y)) {
        return mp_set(R->z, 1);
    }

    if (map) {
        ret = mp_set(R->z, 1);
    }
    else {
        mp_int mu;

        ret = mp_init(&mu);
        if (ret == MP_OKAY) {
            ret = mp_montgomery_calc_normalization(&mu, modulus);
            if (ret == MP_OKAY) {
                ret = mp_mulmod(R->x, &mu, modulus, R->x);
            }
            if (ret == MP_OKAY) {
                ret = mp_mulmod(R->y, &mu, modulus, R->y);
            }
            if (ret == MP_OKAY) {
                ret = mp_copy(&mu, R->z);
            }
            mp_clear(&mu);
        }
    }

    return ret;
}

#if defined(WOLFSSL_HW_METRICS)
int esp_hw_show_ecc_metrics(void)
{
    ESP_LOGI("wolf_hw_ecc", "ECC point multiply HW calls = %lu",
        esp32_ecc_mul_usage_ct);
    ESP_LOGI("wolf_hw_ecc", "ECDSA verify HW calls = %lu",
        esp32_ecdsa_verify_usage_ct);
    return ESP_OK;
}
#endif

#endif /* WOLFSSL_ESP32_CRYPT_ECC || WOLFSSL_ESP32_CRYPT_ECDSA */
#endif /* WOLFSSL_ESPIDF && HAVE_ECC */
