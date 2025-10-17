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

#if LIBSPDM_ML_DSA_44_SUPPORT
    uint8_t signature_44[2420];
    size_t sig_size_44;
    void *dsa_context_44;

    sig_size_44 = sizeof(signature_44);
    libspdm_zero_mem(signature_44, sig_size_44);

    /* KAT Vectors */
    extern const uint8_t message_hash_44[35];
    extern const uint8_t priv_key_44[2560];
    extern const uint8_t public_key_44[1312];
    extern const uint8_t sign_context_44[208];
    extern const uint8_t expected_signature_44[2420];

    dsa_context_44 = libspdm_mldsa_new(LIBSPDM_CRYPTO_NID_ML_DSA_44);
    if (dsa_context_44 == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_44 new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_pubkey(dsa_context_44, public_key_44, sizeof(public_key_44));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_44 set public_key_44 failed \n"));
        libspdm_mldsa_free(dsa_context_44);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_privkey(dsa_context_44, priv_key_44, sizeof(priv_key_44));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_44 set priv_key_44 failed \n"));
        libspdm_mldsa_free(dsa_context_44);
        result = false;
        goto update;
    }

    /*mldsa KAT test*/
    result = libspdm_mldsa_sign_ex(dsa_context_44,
                                   sign_context_44, sizeof(sign_context_44),
                                   message_hash_44, sizeof(message_hash_44),
                                   signature_44, &sig_size_44,
                                   true);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-44 sign failed \n"));
        libspdm_mldsa_free(dsa_context_44);
        result = false;
        goto update;
    }

    if (sig_size_44 != sizeof(expected_signature_44)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-44 KAT failed \n"));
        libspdm_mldsa_free(dsa_context_44);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature_44, expected_signature_44,
                                        sizeof(expected_signature_44))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-44 KAT failed \n"));
        libspdm_mldsa_free(dsa_context_44);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_verify(dsa_context_44,
                                  sign_context_44, sizeof(sign_context_44),
                                  message_hash_44, sizeof(message_hash_44),
                                  signature_44, sig_size_44);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-44 selftest failed \n"));
        libspdm_mldsa_free(dsa_context_44);
        result = false;
        goto update;
    }

    libspdm_mldsa_free(dsa_context_44);
#endif/*LIBSPDM_ML_DSA_44_SUPPORT*/

#if LIBSPDM_ML_DSA_65_SUPPORT
    uint8_t signature_65[3309];
    size_t sig_size_65;
    void *dsa_context_65;

    sig_size_65 = sizeof(signature_65);
    libspdm_zero_mem(signature_65, sig_size_65);

    /* KAT Vectors */
    extern const uint8_t message_hash_65[84];
    extern const uint8_t priv_key_65[4032];
    extern const uint8_t public_key_65[1952];
    extern const uint8_t sign_context_65[24];
    extern const uint8_t expected_signature_65[3309];

    dsa_context_65 = libspdm_mldsa_new(LIBSPDM_CRYPTO_NID_ML_DSA_65);
    if (dsa_context_65 == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_65 new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_pubkey(dsa_context_65, public_key_65, sizeof(public_key_65));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_65 set public_key_65 failed \n"));
        libspdm_mldsa_free(dsa_context_65);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_privkey(dsa_context_65, priv_key_65, sizeof(priv_key_65));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_65 set priv_key_65 failed \n"));
        libspdm_mldsa_free(dsa_context_65);
        result = false;
        goto update;
    }

    /*mldsa KAT test*/
    result = libspdm_mldsa_sign_ex(dsa_context_65,
                                   sign_context_65, sizeof(sign_context_65),
                                   message_hash_65, sizeof(message_hash_65),
                                   signature_65, &sig_size_65,
                                   true);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-65 sign failed \n"));
        libspdm_mldsa_free(dsa_context_65);
        result = false;
        goto update;
    }

    if (sig_size_65 != sizeof(expected_signature_65)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-65 KAT failed \n"));
        libspdm_mldsa_free(dsa_context_65);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature_65, expected_signature_65,
                                        sizeof(expected_signature_65))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-65 KAT failed \n"));
        libspdm_mldsa_free(dsa_context_65);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_verify(dsa_context_65,
                                  sign_context_65, sizeof(sign_context_65),
                                  message_hash_65, sizeof(message_hash_65),
                                  signature_65, sig_size_65);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-65 selftest failed \n"));
        libspdm_mldsa_free(dsa_context_65);
        result = false;
        goto update;
    }

    libspdm_mldsa_free(dsa_context_65);
#endif/*LIBSPDM_ML_DSA_65_SUPPORT*/

#if LIBSPDM_ML_DSA_87_SUPPORT
    uint8_t signature_87[4627];
    size_t sig_size_87;
    void *dsa_context_87;

    sig_size_87 = sizeof(signature_87);
    libspdm_zero_mem(signature_87, sig_size_87);

    /* KAT Vectors */
    extern const uint8_t message_hash_87[94];
    extern const uint8_t priv_key_87[4896];
    extern const uint8_t public_key_87[2592];
    extern const uint8_t sign_context_87[208];
    extern const uint8_t expected_signature_87[4627];

    dsa_context_87 = libspdm_mldsa_new(LIBSPDM_CRYPTO_NID_ML_DSA_87);
    if (dsa_context_87 == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_87 new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_pubkey(dsa_context_87, public_key_87, sizeof(public_key_87));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_87 set public_key_87 failed \n"));
        libspdm_mldsa_free(dsa_context_87);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_set_privkey(dsa_context_87, priv_key_87, sizeof(priv_key_87));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "dsa_context_87 set priv_key_87 failed \n"));
        libspdm_mldsa_free(dsa_context_87);
        result = false;
        goto update;
    }

    /*mldsa KAT test*/
    result = libspdm_mldsa_sign_ex(dsa_context_87,
                                   sign_context_87, sizeof(sign_context_87),
                                   message_hash_87, sizeof(message_hash_87),
                                   signature_87, &sig_size_87,
                                   true);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 sign failed \n"));
        libspdm_mldsa_free(dsa_context_87);
        result = false;
        goto update;
    }

    if (sig_size_87 != sizeof(expected_signature_87)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 KAT failed \n"));
        libspdm_mldsa_free(dsa_context_87);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(signature_87, expected_signature_87,
                                        sizeof(expected_signature_87))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 KAT failed \n"));
        libspdm_mldsa_free(dsa_context_87);
        result = false;
        goto update;
    }

    result = libspdm_mldsa_verify(dsa_context_87,
                                  sign_context_87, sizeof(sign_context_87),
                                  message_hash_87, sizeof(message_hash_87),
                                  signature_87, sig_size_87);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-DSA-87 selftest failed \n"));
        libspdm_mldsa_free(dsa_context_87);
        result = false;
        goto update;
    }

    libspdm_mldsa_free(dsa_context_87);
#endif/*LIBSPDM_ML_DSA_87_SUPPORT*/

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
