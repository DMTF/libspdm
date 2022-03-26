/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "test_crypt.h"

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_hkdf_sha256_ikm[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b
};

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_hkdf_sha256_salt[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c,
};

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_hkdf_sha256_info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_hkdf_sha256_prk[32] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
    0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
    0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
    0xb3, 0xe5,
};

GLOBAL_REMOVE_IF_UNREFERENCED uint8_t m_libspdm_hkdf_sha256_okm[42] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43,
    0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90,
    0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
    0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65,
};

/**
 * Validate Crypto HMAC Key Derivation Function Interfaces.
 *
 * @retval  true  Validation succeeded.
 * @retval  false  Validation failed.
 *
 **/
bool libspdm_validate_crypt_hkdf(void)
{
    uint8_t prk_out[32];
    uint8_t out[42];
    bool status;

    libspdm_my_print(" \nCrypto HKDF Engine Testing:\n");

    libspdm_my_print("- HKDF-SHA256: ");

    /* HKDF-SHA-256 digest Validation*/

    libspdm_my_print("extract... ");
    libspdm_zero_mem(prk_out, sizeof(prk_out));
    status = libspdm_hkdf_sha256_extract (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        prk_out, sizeof(prk_out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (libspdm_const_compare_mem(prk_out, m_libspdm_hkdf_sha256_prk,
                                  sizeof(m_libspdm_hkdf_sha256_prk)) !=
        0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("expand... ");
    status = libspdm_hkdf_sha256_expand (
        m_libspdm_hkdf_sha256_prk, sizeof(m_libspdm_hkdf_sha256_prk),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (libspdm_const_compare_mem(out, m_libspdm_hkdf_sha256_okm,
                                  sizeof(m_libspdm_hkdf_sha256_okm)) !=
        0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("extract_and_expand... ");
    status = libspdm_hkdf_sha256_extract_and_expand (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("Check value... ");
    if (libspdm_const_compare_mem(out, m_libspdm_hkdf_sha256_okm,
                                  sizeof(m_libspdm_hkdf_sha256_okm)) !=
        0) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");

    libspdm_my_print("- HKDF-SHA3_256: ");

    /* HKDF-SHA3-256 digest Validation*/

    libspdm_my_print("extract... ");
    libspdm_zero_mem(prk_out, sizeof(prk_out));
    status = libspdm_hkdf_sha3_256_extract (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        prk_out, sizeof(prk_out)
        );
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return true;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("expand... ");
    status = libspdm_hkdf_sha3_256_expand (
        m_libspdm_hkdf_sha256_prk, sizeof(m_libspdm_hkdf_sha256_prk),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("extract_and_expand... ");
    status = libspdm_hkdf_sha3_256_extract_and_expand (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");

    libspdm_my_print("- HKDF-SM3_256: ");

    /* HKDF-SM3-256 digest Validation*/

    libspdm_my_print("extract... ");
    libspdm_zero_mem(prk_out, sizeof(prk_out));
    status = libspdm_hkdf_sm3_256_extract (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        prk_out, sizeof(prk_out)
        );
    if (!status) {
        libspdm_my_print("[Fail]\n");
        return true;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("expand... ");
    status = libspdm_hkdf_sm3_256_expand (
        m_libspdm_hkdf_sha256_prk, sizeof(m_libspdm_hkdf_sha256_prk),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    libspdm_my_print("extract_and_expand... ");
    status = libspdm_hkdf_sm3_256_extract_and_expand (
        m_libspdm_hkdf_sha256_ikm, sizeof(m_libspdm_hkdf_sha256_ikm),
        m_libspdm_hkdf_sha256_salt, sizeof(m_libspdm_hkdf_sha256_salt),
        m_libspdm_hkdf_sha256_info, sizeof(m_libspdm_hkdf_sha256_info),
        out, sizeof(out)
        );
    if (!status) {
        libspdm_my_print("[Fail]");
        return false;
    }

    libspdm_my_print("[Pass]\n");

    return true;
}
