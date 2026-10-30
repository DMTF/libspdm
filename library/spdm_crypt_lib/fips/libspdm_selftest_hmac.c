/**
 *  Copyright Notice:
 *  Copyright 2023-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

void libspdm_fips_selftest_hmac_sha256(void *fips_selftest_context)
{
#if LIBSPDM_SHA256_SUPPORT
    bool result = true;

    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256) != 0) {
        return;
    }

    /* Test vector (key, msg and mac, truncated to 20 bytes) from the NIST
     * ACVP-Server: HMAC-SHA2-256-1.0/internalProjection.json.
     * https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-256-1.0
     */
    const uint8_t key[] = {
        0x3d, 0xee, 0x0e, 0x8c, 0x74, 0x73, 0x55, 0x12,
        0x09, 0xd3, 0x29, 0xfa, 0x3c, 0x04, 0x35, 0xd4,
        0x5f, 0x7e, 0x9f
    };
    const uint8_t msg[] = {
        0xa5, 0xc3, 0xdb, 0xeb, 0x8c, 0xdc, 0x2f, 0xa7,
        0xa1, 0x15, 0xeb, 0x17, 0x7f, 0x47, 0xb5, 0x8f
    };

    uint8_t hmac_256_result[32];
    const uint8_t hmac_sha256_answer[] = {
        0x7c, 0xd5, 0xb1, 0xba, 0x13, 0xf1, 0x77, 0x24,
        0x82, 0xfb, 0x68, 0xde, 0x3c, 0xac, 0x67, 0x11,
        0xc7, 0x06, 0xf0, 0x4a
    };
    libspdm_zero_mem(hmac_256_result, sizeof(hmac_256_result));
    result = libspdm_hmac_sha256_all(msg, sizeof(msg), key, sizeof(key), hmac_256_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen hmac_sha256 failed \n"));
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(hmac_256_result, hmac_sha256_answer,
                                        sizeof(hmac_sha256_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "hmac_sha256 KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_HMAC_SHA256;
    }

#endif/*LIBSPDM_SHA256_SUPPORT*/
}

void libspdm_fips_selftest_hmac_sha384(void *fips_selftest_context)
{
#if LIBSPDM_SHA384_SUPPORT
    bool result = true;

    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384) != 0) {
        return;
    }

    /* Test vector (key, msg and mac, truncated to 20 bytes) from the NIST
     * ACVP-Server: HMAC-SHA2-384-1.0/internalProjection.json.
     * https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-384-1.0
     */
    const uint8_t key[] = {
        0x21
    };
    const uint8_t msg[] = {
        0xd4, 0x6d, 0xf0, 0x72, 0xe6, 0xb8, 0x09, 0xca,
        0x58, 0x25, 0x08, 0xf7, 0x78, 0xb9, 0x5f, 0xe9
    };

    uint8_t hmac_384_result[48];
    const uint8_t hmac_sha384_answer[] = {
        0x64, 0x98, 0x1a, 0xfe, 0xa4, 0x65, 0x5e, 0x46,
        0xb6, 0x0d, 0x7a, 0xb9, 0xad, 0xb3, 0x56, 0xe1,
        0x53, 0x86, 0xd9, 0x58
    };
    libspdm_zero_mem(hmac_384_result, sizeof(hmac_384_result));
    result = libspdm_hmac_sha384_all(msg, sizeof(msg), key, sizeof(key), hmac_384_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen hmac_sha384 failed \n"));
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(hmac_384_result, hmac_sha384_answer,
                                        sizeof(hmac_sha384_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "hmac_sha384 KAT failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_HMAC_SHA384;
    }

#endif/*LIBSPDM_SHA384_SUPPORT*/
}

void libspdm_fips_selftest_hmac_sha512(void *fips_selftest_context)
{
#if LIBSPDM_SHA512_SUPPORT
    bool result = true;

    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512) != 0) {
        return;
    }

    /* Test vector (key, msg and mac, truncated to 20 bytes) from the NIST
     * ACVP-Server: HMAC-SHA2-512-1.0/internalProjection.json.
     * https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/HMAC-SHA2-512-1.0
     */
    const uint8_t key[] = {
        0x6a
    };
    const uint8_t msg[] = {
        0x69, 0x6a, 0x10, 0x94, 0x96, 0xc0, 0xd7, 0x6a,
        0x83, 0x45, 0x6f, 0x8c, 0x48, 0x5f, 0x54, 0xa6
    };

    uint8_t hmac_512_result[64];
    const uint8_t hmac_sha512_answer[] = {
        0x10, 0x51, 0x23, 0x85, 0x71, 0x56, 0x3b, 0xfa,
        0x7a, 0x50, 0x4f, 0x17, 0x52, 0x96, 0x4a, 0x06,
        0xa3, 0xb3, 0x08, 0x7a
    };
    libspdm_zero_mem(hmac_512_result, sizeof(hmac_512_result));
    result = libspdm_hmac_sha512_all(msg, sizeof(msg), key, sizeof(key), hmac_512_result);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "gen hmac_sha512 failed \n"));
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(hmac_512_result, hmac_sha512_answer,
                                        sizeof(hmac_sha512_answer))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "hmac_sha512 KAT failed \n"));
        result = false;
        goto update;
    }
update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_HMAC_SHA512;
    }

#endif/*LIBSPDM_SHA512_SUPPORT*/
}

#endif/*LIBSPDM_FIPS_MODE*/
