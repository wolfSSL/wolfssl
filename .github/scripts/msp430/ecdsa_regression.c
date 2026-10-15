/* ecdsa_regression.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <string.h>

/* Captured from the simulator's deterministic fixture and independently
 * verified with OpenSSL. NO_ASN uses the raw, fixed-width R || S encoding.
 * TI GCC 9.3.1.11 -Os previously rejected this valid signature when an
 * unsaved R9 clobber corrupted the SP modular-inverse loop counter. */
static const byte publicKey[] = {
    0x04, 0x75, 0x99, 0xb1, 0xef, 0xb6, 0x7a, 0x08,
    0x1c, 0xf5, 0x18, 0x88, 0xfb, 0x99, 0xdd, 0xc4,
    0x57, 0x27, 0x57, 0xf6, 0xc6, 0x37, 0xab, 0x2d,
    0xf2, 0x6f, 0x89, 0x5a, 0xe4, 0x02, 0x32, 0x0e,
    0x80, 0x94, 0x54, 0xec, 0x3f, 0xea, 0x5b, 0x50,
    0xcc, 0x3a, 0xf9, 0xf6, 0x3d, 0xae, 0x7a, 0xf4,
    0xc3, 0x76, 0x76, 0xc0, 0x4b, 0xab, 0x0c, 0xcc,
    0xf4, 0xc2, 0x20, 0x3c, 0xe4, 0x13, 0xcc, 0x85,
    0x0e
};
static const byte digest[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const byte signature[] = {
    0x00, 0xf2, 0x45, 0x05, 0x14, 0x4d, 0xda, 0x27,
    0x75, 0x28, 0x5a, 0x3b, 0x0f, 0x26, 0xad, 0x7d,
    0x0f, 0xcf, 0xb6, 0xcb, 0xf7, 0x73, 0xc9, 0xc7,
    0x25, 0x19, 0xda, 0x02, 0xe5, 0x60, 0x8d, 0xc2,
    0xa2, 0xce, 0xba, 0xc1, 0x64, 0x83, 0x6a, 0x7d,
    0xdb, 0x2b, 0x2b, 0xb5, 0x24, 0x59, 0xc0, 0xda,
    0xa0, 0xe8, 0x5e, 0x88, 0x1e, 0x8c, 0x32, 0x79,
    0x92, 0x86, 0x16, 0x65, 0xc8, 0xf4, 0xd0, 0xe9
};

int msp430_ecdsa_regression(void)
{
    ecc_key key;
    byte changedDigest[sizeof(digest)];
    byte changedSignature[sizeof(signature)];
    int valid = 0;
    int ret;

    ret = wc_ecc_init(&key);
    if (ret != 0)
        return ret;
    ret = wc_ecc_import_x963_ex(publicKey, sizeof(publicKey), &key,
        ECC_SECP256R1);
    if (ret == 0) {
        ret = wc_ecc_verify_hash(signature, sizeof(signature), digest,
            sizeof(digest), &valid, &key);
        if (ret == 0 && valid != 1)
            ret = -1;
    }
    if (ret == 0) {
        memcpy(changedDigest, digest, sizeof(digest));
        changedDigest[0] ^= 1;
        valid = 1;
        ret = wc_ecc_verify_hash(signature, sizeof(signature), changedDigest,
            sizeof(changedDigest), &valid, &key);
        if (ret == 0 && valid != 0)
            ret = -1;
    }
    if (ret == 0) {
        memcpy(changedSignature, signature, sizeof(signature));
        changedSignature[sizeof(changedSignature) - 1] ^= 1;
        valid = 1;
        ret = wc_ecc_verify_hash(changedSignature, sizeof(changedSignature),
            digest, sizeof(digest), &valid, &key);
        if (ret == 0 && valid != 0)
            ret = -1;
    }
    wc_ecc_free(&key);
    return ret;
}
