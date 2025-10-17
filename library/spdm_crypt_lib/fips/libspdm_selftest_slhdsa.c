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
 * slhdsa self_test
 **/
bool libspdm_fips_selftest_slhdsa(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SLH_DSA_SUPPORT
    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_SLH_DSA) != 0) {
        return true;
    }

    uint8_t *signature;
    size_t sig_size;
    void *dsa_context;

    sig_size = 7856;
    LIBSPDM_ASSERT(context->selftest_buffer_size >= sig_size);
    LIBSPDM_ASSERT(context->selftest_buffer != NULL);
    libspdm_zero_mem(context->selftest_buffer, context->selftest_buffer_size);
    signature = context->selftest_buffer;

    /* KAT Vectors */
    extern const uint8_t message_hash_sha2_128s[262];
    extern const uint8_t priv_key_sha2_128s[64];
    extern const uint8_t public_key_sha2_128s[32];
    extern const uint8_t sign_context_sha2_128s[158];
    extern const uint8_t expected_signature_sha2_128s[7856];

    dsa_context = libspdm_slhdsa_new(LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_128S);
    if (dsa_context == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_slhdsa_set_pubkey(dsa_context, public_key_sha2_128s, sizeof(public_key_sha2_128s));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context set public_key failed \n"));
        libspdm_slhdsa_free(dsa_context);
        result = false;
        goto update;
    }

    result = libspdm_slhdsa_set_privkey(dsa_context, priv_key_sha2_128s, sizeof(priv_key_sha2_128s));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context set priv_key failed \n"));
        libspdm_slhdsa_free(dsa_context);
        result = false;
        goto update;
    }

    /*mldsa KAT test*/
    result = libspdm_slhdsa_sign_ex(dsa_context,
                                    sign_context_sha2_128s, sizeof(sign_context_sha2_128s),
                                    message_hash_sha2_128s, sizeof(message_hash_sha2_128s),
                                    signature, &sig_size,
                                    true);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-128S sign failed \n"));
        libspdm_slhdsa_free(dsa_context);
        result = false;
        goto update;
    }

    if (sig_size != sizeof(expected_signature_sha2_128s)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-128S KAT failed \n"));
        libspdm_slhdsa_free(dsa_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature, expected_signature_sha2_128s,
                                        sizeof(expected_signature_sha2_128s))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-128S KAT failed \n"));
        libspdm_slhdsa_free(dsa_context);
        result = false;
        goto update;
    }

    result = libspdm_slhdsa_verify(dsa_context,
                                   sign_context_sha2_128s, sizeof(sign_context_sha2_128s),
                                   message_hash_sha2_128s, sizeof(message_hash_sha2_128s),
                                   signature, sig_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-128S selftest failed \n"));
        libspdm_slhdsa_free(dsa_context);
        result = false;
        goto update;
    }

    libspdm_slhdsa_free(dsa_context);
update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SLH_DSA;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SLH_DSA;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SLH_DSA;
    }

#endif/*LIBSPDM_SLH_DSA_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
