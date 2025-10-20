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
 * ML-KEM self_test
 **/
bool libspdm_fips_selftest_mlkem(void *fips_selftest_context)
{
    bool result = true;

#if LIBSPDM_ML_KEM_SUPPORT
    libspdm_fips_selftest_context_t *context = fips_selftest_context;
    LIBSPDM_ASSERT(fips_selftest_context != NULL);

    /* any test fail cause the FIPS fail*/
    if (context->tested_algo != context->self_test_result) {
        return false;
    }

    /* check if run before.*/
    if ((context->tested_algo & LIBSPDM_FIPS_SELF_TEST_ML_KEM) != 0) {
        return true;
    }

    void *kem_context;
    uint8_t shared_secret[32];
    size_t shared_secret_size;
    uint8_t *cipher_text;
    size_t cipher_text_size;

    shared_secret_size = sizeof(shared_secret);
    libspdm_zero_mem(shared_secret, shared_secret_size);

    cipher_text_size = 1568;
    LIBSPDM_ASSERT(context->selftest_buffer_size >= cipher_text_size);
    LIBSPDM_ASSERT(context->selftest_buffer != NULL);
    libspdm_zero_mem(context->selftest_buffer, context->selftest_buffer_size);
    cipher_text = context->selftest_buffer;

    extern uint8_t peer_encap_key_mlkem_1024[1568];
    extern uint8_t decap_key_mlkem_1024[3168];
    extern uint8_t expected_cipher_text_mlkem_1024[1568];
    extern uint8_t expected_shared_secret_mlkem_1024[32];
    extern uint8_t random_value_mlkem_1024[32];

    kem_context = libspdm_mlkem_new_by_name(LIBSPDM_CRYPTO_NID_ML_KEM_1024);
    if (kem_context == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM new failed \n"));
        result = false;
        goto update;
    }

    result = libspdm_mlkem_encapsulate_ex(kem_context, peer_encap_key_mlkem_1024,
                                          sizeof(peer_encap_key_mlkem_1024),
                                          cipher_text, &cipher_text_size,
                                          shared_secret, &shared_secret_size,
                                          random_value_mlkem_1024, sizeof(random_value_mlkem_1024));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM encapsulate failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    /*KAT test*/
    if (cipher_text_size != sizeof(expected_cipher_text_mlkem_1024)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM KAT failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(cipher_text, expected_cipher_text_mlkem_1024,
                                        sizeof(expected_cipher_text_mlkem_1024))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM KAT failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    if (shared_secret_size != sizeof(expected_shared_secret_mlkem_1024)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM KAT failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(shared_secret, expected_shared_secret_mlkem_1024,
                                        sizeof(expected_shared_secret_mlkem_1024))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM KAT failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    result = libspdm_mlkem_set_privkey(kem_context, decap_key_mlkem_1024, sizeof(decap_key_mlkem_1024));
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM set private key failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    result = libspdm_mlkem_decapsulate(kem_context, cipher_text, cipher_text_size,
                                       shared_secret, &shared_secret_size);
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM decapsulate failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    if (shared_secret_size != sizeof(expected_shared_secret_mlkem_1024)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM KAT failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

    if (!libspdm_consttime_is_mem_equal(shared_secret, expected_shared_secret_mlkem_1024,
                                        sizeof(expected_shared_secret_mlkem_1024))) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "ML-KEM KAT failed \n"));
        libspdm_mlkem_free(kem_context);
        result = false;
        goto update;
    }

update:
    /* mark it as tested*/
    context->tested_algo |= LIBSPDM_FIPS_SELF_TEST_ML_KEM;

    /* record test result*/
    if (result) {
        context->self_test_result |= LIBSPDM_FIPS_SELF_TEST_ML_KEM;
    } else {
        context->self_test_result &= ~LIBSPDM_FIPS_SELF_TEST_ML_KEM;
    }

#endif/*LIBSPDM_ML_KEM_SUPPORT*/

    return result;
}

#endif/*LIBSPDM_FIPS_MODE*/
