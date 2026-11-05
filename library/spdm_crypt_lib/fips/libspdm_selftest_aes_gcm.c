/**
 *  Copyright Notice:
 *  Copyright 2023-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

void libspdm_fips_selftest_aes_gcm(void *fips_selftest_context)
{
#if LIBSPDM_AEAD_GCM_SUPPORT
    bool result = true;

    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_AES_GCM) != 0) {
        return;
    }

    uint8_t output_ciphertext[1024];
    uint8_t output_plaintext[1024];
    uint8_t output_tag[1024];
    size_t output_ciphertext_size;
    size_t output_plaintext_size;

    output_ciphertext_size = sizeof(output_ciphertext);
    output_plaintext_size = sizeof(output_plaintext);

    /*Key to use crypto operation*/
    /* Test vector (key, iv, pt, aad, ct and tag) from the NIST CAVP:
     * gcmtestvectors.zip, gcmEncryptExtIV128.rsp, [Keylen = 128, IVlen = 96,
     * PTlen = 128, AADlen = 128, Taglen = 128], first record.
     * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
     */
    const uint8_t key[] = {
        0xc9, 0x39, 0xcc, 0x13, 0x39, 0x7c, 0x1d, 0x37,
        0xde, 0x6a, 0xe0, 0xe1, 0xcb, 0x7c, 0x42, 0x3c
    };

    /*IV to perform the crypto operation upon*/
    const uint8_t iv[] = {
        0xb3, 0xd8, 0xcc, 0x01, 0x7c, 0xbb, 0x89, 0xb3,
        0x9e, 0x0f, 0x67, 0xe2
    };

    /*Data to perform the crypto operation upon*/
    const uint8_t input[] = {
        0xc3, 0xb3, 0xc4, 0x1f, 0x11, 0x3a, 0x31, 0xb7,
        0x3d, 0x9a, 0x5c, 0xd4, 0x32, 0x10, 0x30, 0x69
    };

    /*Additional auth data*/
    const uint8_t aad[] = {
        0x24, 0x82, 0x56, 0x02, 0xbd, 0x12, 0xa9, 0x84,
        0xe0, 0x09, 0x2d, 0x3e, 0x44, 0x8e, 0xda, 0x5f
    };

    /*Expected ciphertext*/
    const uint8_t expected_ciphertext[] = {
        0x93, 0xfe, 0x7d, 0x9e, 0x9b, 0xfd, 0x10, 0x34,
        0x8a, 0x56, 0x06, 0xe5, 0xca, 0xfa, 0x73, 0x54
    };

    /*Expected Auth Tag*/
    const uint8_t expected_tag[] = {
        0x00, 0x32, 0xa1, 0xdc, 0x85, 0xf1, 0xc9, 0x78,
        0x69, 0x25, 0xa2, 0xe7, 0x1d, 0x82, 0x72, 0xdd
    };

    /*KAT test*/
    libspdm_zero_mem(output_ciphertext, sizeof(output_ciphertext));
    libspdm_zero_mem(output_tag, sizeof(output_tag));
    result = libspdm_aead_aes_gcm_encrypt(key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad),
                                          input, sizeof(input), output_tag, sizeof(expected_tag),
                                          output_ciphertext, &output_ciphertext_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm encrypt failed \n"));
        goto update;
    }

    if (output_ciphertext_size != sizeof(expected_ciphertext)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm KAT failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(output_ciphertext, expected_ciphertext,
                                        sizeof(expected_ciphertext))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm KAT failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(output_tag, expected_tag, sizeof(expected_tag))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm KAT failed \n"));
        result = false;
        goto update;
    }

    libspdm_zero_mem(output_plaintext, sizeof(output_plaintext));
    result = libspdm_aead_aes_gcm_decrypt(key, sizeof(key), iv, sizeof(iv), aad, sizeof(aad),
                                          expected_ciphertext, sizeof(expected_ciphertext),
                                          expected_tag, sizeof(expected_tag),
                                          output_plaintext, &output_plaintext_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm decrypt failed \n"));
        result = false;
        goto update;
    }

    if (output_plaintext_size != sizeof(input)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm selftest failed \n"));
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(output_plaintext, input, sizeof(input))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "aes_gcm selftest failed \n"));
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_AES_GCM;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_AES_GCM;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_AES_GCM;
    }

#endif/*LIBSPDM_AEAD_GCM_SUPPORT*/
}

#endif
