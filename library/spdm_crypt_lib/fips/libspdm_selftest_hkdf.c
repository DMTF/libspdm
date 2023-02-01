/**
 *  Copyright Notice:
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "spdm_crypt_ext_lib/cryptlib_ext.h"

#if LIBSPDM_FIPS_MODE

/**
 * HKDF KAT test
 **/
bool libspdm_fips_selftest_hkdf(void)
{
    bool result = true;

#if LIBSPDM_SHA256_SUPPORT
    uint8_t prk_out[32];
    uint8_t out[42];

    /* Test Vectors https://www.rfc-editor.org/rfc/rfc5869.html */
    uint8_t hkdf_sha256_ikm[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b
    };

    uint8_t hkdf_sha256_salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c,
    };

    uint8_t hkdf_sha256_info[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };

    uint8_t hkdf_sha256_prk[] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
        0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
        0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    };

    uint8_t hkdf_sha256_okm[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43,
        0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90,
        0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };

    libspdm_zero_mem(prk_out, sizeof(prk_out));
    result = libspdm_hkdf_sha256_extract (
        hkdf_sha256_ikm, sizeof(hkdf_sha256_ikm),
        hkdf_sha256_salt, sizeof(hkdf_sha256_salt),
        prk_out, sizeof(prk_out)
        );
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HKDF extract failed \n"));
        return false;
    }

    if (libspdm_const_compare_mem(prk_out, hkdf_sha256_prk, sizeof(hkdf_sha256_prk)) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HKDF KAT failed \n"));
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    result = libspdm_hkdf_sha256_expand (hkdf_sha256_prk, sizeof(hkdf_sha256_prk),
                                         hkdf_sha256_info, sizeof(hkdf_sha256_info),
                                         out, sizeof(out));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HKDF expand failed \n"));
        return false;
    }

    if (libspdm_const_compare_mem(out, hkdf_sha256_okm, sizeof(hkdf_sha256_okm)) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HKDF KAT failed \n"));
        return false;
    }

    libspdm_zero_mem(out, sizeof(out));
    result = libspdm_hkdf_sha256_extract_and_expand (hkdf_sha256_ikm, sizeof(hkdf_sha256_ikm),
                                                     hkdf_sha256_salt, sizeof(hkdf_sha256_salt),
                                                     hkdf_sha256_info, sizeof(hkdf_sha256_info),
                                                     out, sizeof(out));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HKDF extract and expand failed \n"));
        return false;
    }

    if (libspdm_const_compare_mem(out, hkdf_sha256_okm, sizeof(hkdf_sha256_okm)) != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "HKDF KAT failed \n"));
        return false;
    }

#endif/*LIBSPDM_SHA256_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
