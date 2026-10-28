/**
 *  Copyright Notice:
 *  Copyright 2023-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

void libspdm_fips_selftest_ecdh(void *fips_selftest_context)
{
#if LIBSPDM_ECDHE_SUPPORT
    bool result = true;

    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_ECDH) != 0) {
        return;
    }

    void *ec_context;
    uint8_t common_key[66];
    size_t common_key_length;

    common_key_length = sizeof(common_key);
    libspdm_zero_mem(common_key, common_key_length);
    /* Test vector (private key, peer public key and shared secret) from the
     * NIST CAVP: ecccdhtestvectors.zip, KAS_ECC_CDH_PrimitiveTest.txt,
     * [P-256], COUNT = 0.
     * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing
     */
    /* self private Key*/
    const uint8_t self_privkey[] = {
        0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda,
        0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
        0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e,
        0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
    };

    /* peer public Key*/
    const uint8_t peer_public[] = {
        0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c,
        0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
        0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4,
        0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
        0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06,
        0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
        0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0,
        0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
    };

    /* expected ecdh common secret*/
    const uint8_t expected_ecdh_secret[] = {
        0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01,
        0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
        0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68,
        0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b
    };

    ec_context = libspdm_ec_new_by_nid(LIBSPDM_CRYPTO_NID_ECDSA_NIST_P256);
    if (ec_context == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_ec_set_priv_key(ec_context, self_privkey, sizeof(self_privkey));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH set private key failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    result = libspdm_ec_compute_key(ec_context, peer_public, sizeof(peer_public), common_key,
                                    &common_key_length);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH compute key failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    /*KAT test*/
    if (common_key_length != sizeof(expected_ecdh_secret)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH KAT failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(common_key, expected_ecdh_secret,
                                        sizeof(expected_ecdh_secret))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ECDH KAT failed \n"));
        libspdm_ec_free(ec_context);
        result = false;
        goto update;
    }

    libspdm_ec_free(ec_context);

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_ECDH;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_ECDH;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_ECDH;
    }

#endif/*LIBSPDM_ECDHE_SUPPORT*/
}

#endif/*LIBSPDM_FIPS_MODE*/
