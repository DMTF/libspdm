/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"

#if LIBSPDM_FIPS_MODE

/**
 * mldsa self_test
 **/
bool libspdm_fips_selftest_mldsa(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_ML_DSA_SUPPORT
    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_ML_DSA) != 0) {
        return true;
    }

    uint8_t *signature;
    size_t sig_size;
    void *dsa_context;

    sig_size = 4627;
    LIBSPDM_ASSERT(context->selftest_buffer_size >= sig_size);
    LIBSPDM_ASSERT(context->selftest_buffer != NULL);
    libspdm_zero_mem(context->selftest_buffer, context->selftest_buffer_size);
    signature = context->selftest_buffer;

    /* KAT Vectors */
    extern const uint8_t message_hash_mldsa_87[94];
    extern const uint8_t priv_key_mldsa_87[4896];
    extern const uint8_t public_key_mldsa_87[2592];
    extern const uint8_t sign_context_mldsa_87[208];
    extern const uint8_t expected_signature_mldsa_87[4627];

    dsa_context = libspdm_mldsa_new(LIBSPDM_CRYPTO_NID_ML_DSA_87);
    if (dsa_context == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_pubkey(dsa_context, public_key_mldsa_87, sizeof(public_key_mldsa_87));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context set public_key failed \n"));
        libspdm_mldsa_free(dsa_context);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_privkey(dsa_context, priv_key_mldsa_87, sizeof(priv_key_mldsa_87));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context set priv_key failed \n"));
        libspdm_mldsa_free(dsa_context);
        result = false;
        goto update;
    }

    /*mldsa KAT test*/
    result = libspdm_mldsa_sign_ex(dsa_context,
                                   sign_context_mldsa_87, sizeof(sign_context_mldsa_87),
                                   message_hash_mldsa_87, sizeof(message_hash_mldsa_87),
                                   signature, &sig_size,
                                   true);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 sign failed \n"));
        libspdm_mldsa_free(dsa_context);
        result = false;
        goto update;
    }

    if (sig_size != sizeof(expected_signature_mldsa_87)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 KAT failed \n"));
        libspdm_mldsa_free(dsa_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature, expected_signature_mldsa_87,
                                        sizeof(expected_signature_mldsa_87))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 KAT failed \n"));
        libspdm_mldsa_free(dsa_context);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_verify(dsa_context,
                                  sign_context_mldsa_87, sizeof(sign_context_mldsa_87),
                                  message_hash_mldsa_87, sizeof(message_hash_mldsa_87),
                                  signature, sig_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 selftest failed \n"));
        libspdm_mldsa_free(dsa_context);
        result = false;
        goto update;
    }

    libspdm_mldsa_free(dsa_context);

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_ML_DSA;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_ML_DSA;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_ML_DSA;
    }

#endif/*LIBSPDM_ML_DSA_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
