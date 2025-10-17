/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_crypt_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_fips_lib.h"
#include "library/malloclib.h"

#if LIBSPDM_FIPS_MODE

/**
 * slhdsa self_test
 **/
bool libspdm_fips_selftest_slhdsa(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT
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
    void *slhdsa_context;

    sig_size = 29792;
    signature = allocate_zero_pool(sig_size);
    if (signature == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "signature allocation failed \n"));
        result = false;
        goto update;
    }

    /* KAT Vectors */
    extern const uint8_t message_hash_sha2_256s[1];
    extern const uint8_t priv_key_sha2_256s[128];
    extern const uint8_t public_key_sha2_256s[64];
    extern const uint8_t sign_context_sha2_256s[254];
    extern const uint8_t expected_signature_sha2_256s[29792];

    slhdsa_context = libspdm_slhdsa_new(LIBSPDM_CRYPTO_NID_SLH_DSA_SHA2_256S);
    if (slhdsa_context == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "slhdsa_context new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_slhdsa_set_pubkey(slhdsa_context, public_key_sha2_256s, sizeof(public_key_sha2_256s));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "slhdsa_context set public_key failed \n"));
        libspdm_slhdsa_free(slhdsa_context);
        result = false;
        goto update;
    }

    result = libspdm_slhdsa_set_privkey(slhdsa_context, priv_key_sha2_256s, sizeof(priv_key_sha2_256s));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "slhdsa_context set priv_key failed \n"));
        libspdm_slhdsa_free(slhdsa_context);
        result = false;
        goto update;
    }

    /*mldsa KAT test*/
    result = libspdm_slhdsa_sign_ex(slhdsa_context,
                                    sign_context_sha2_256s, sizeof(sign_context_sha2_256s),
                                    message_hash_sha2_256s, sizeof(message_hash_sha2_256s),
                                    signature, &sig_size,
                                    true);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-256S sign failed \n"));
        libspdm_slhdsa_free(slhdsa_context);
        result = false;
        goto update;
    }

    if (sig_size != sizeof(expected_signature_sha2_256s)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-256S KAT failed \n"));
        libspdm_slhdsa_free(slhdsa_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature, expected_signature_sha2_256s,
                                        sizeof(expected_signature_sha2_256s))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-256S KAT failed \n"));
        libspdm_slhdsa_free(slhdsa_context);
        result = false;
        goto update;
    }

    result = libspdm_slhdsa_verify(slhdsa_context,
                                   sign_context_sha2_256s, sizeof(sign_context_sha2_256s),
                                   message_hash_sha2_256s, sizeof(message_hash_sha2_256s),
                                   signature, sig_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "SLH-DSA-SHA2-256S selftest failed \n"));
        libspdm_slhdsa_free(slhdsa_context);
        result = false;
        goto update;
    }

    libspdm_slhdsa_free(slhdsa_context);
update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_SLH_DSA;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_SLH_DSA;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_SLH_DSA;
    }

#endif/*LIBSPDM_SLH_DSA_SHA2_256S_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
