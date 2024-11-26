/**
 *  Copyright Notice:
 *  Copyright 2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"
#include "internal/libspdm_common_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_requester_data_pqc_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t req_pqc_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        result = libspdm_read_requester_pqc_private_key(
            req_pqc_asym_alg, &private_pem, &private_pem_size);
        if (!result) {
            return false;
        }

        result = libspdm_req_pqc_asym_get_private_key_from_pem(req_pqc_asym_alg,
                                                               private_pem,
                                                               private_pem_size, NULL,
                                                               &context);
        if (!result) {
            libspdm_zero_mem(private_pem, private_pem_size);
            free(private_pem);
            return false;
        }

        if (is_data_hash) {
            result = libspdm_req_pqc_asym_sign_hash(spdm_version, op_code, req_pqc_asym_alg,
                                                    base_hash_algo, context,
                                                    message, message_size, signature, sig_size);
        } else {
            result = libspdm_req_pqc_asym_sign(spdm_version, op_code, req_pqc_asym_alg,
                                               base_hash_algo, context,
                                               message, message_size,
                                               signature, sig_size);
        }
        libspdm_req_pqc_asym_free(req_pqc_asym_alg, context);
        libspdm_zero_mem(private_pem, private_pem_size);
        free(private_pem);
    } else {
#endif
    result = libspdm_get_requester_pqc_private_key_from_raw_data(req_pqc_asym_alg, &context);
    if (!result) {
        return false;
    }

    if (is_data_hash) {
        result = libspdm_req_pqc_asym_sign_hash(spdm_version, op_code, req_pqc_asym_alg,
                                                base_hash_algo, context,
                                                message, message_size, signature, sig_size);
    } else {
        result = libspdm_req_pqc_asym_sign(spdm_version, op_code, req_pqc_asym_alg,
                                           base_hash_algo, context,
                                           message, message_size,
                                           signature, sig_size);
    }
    libspdm_req_pqc_asym_free(req_pqc_asym_alg, context);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_responder_data_pqc_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t pqc_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        result = libspdm_read_responder_pqc_private_key(
            pqc_asym_algo, &private_pem, &private_pem_size);
        if (!result) {
            return false;
        }

        result = libspdm_pqc_asym_get_private_key_from_pem(
            pqc_asym_algo, private_pem, private_pem_size, NULL, &context);
        if (!result) {
            libspdm_zero_mem(private_pem, private_pem_size);
            free(private_pem);
            return false;
        }

        if (is_data_hash) {
            result = libspdm_pqc_asym_sign_hash(spdm_version, op_code, pqc_asym_algo, base_hash_algo,
                                                context,
                                                message, message_size, signature, sig_size);
        } else {
            result = libspdm_pqc_asym_sign(spdm_version, op_code, pqc_asym_algo,
                                           base_hash_algo, context,
                                           message, message_size,
                                           signature, sig_size);
        }
        libspdm_pqc_asym_free(pqc_asym_algo, context);
        libspdm_zero_mem(private_pem, private_pem_size);
        free(private_pem);
    } else {
#endif
    result = libspdm_get_responder_pqc_private_key_from_raw_data(pqc_asym_algo, &context);
    if (!result) {
        return false;
    }

    if (is_data_hash) {
        result = libspdm_pqc_asym_sign_hash(spdm_version, op_code, pqc_asym_algo, base_hash_algo,
                                            context,
                                            message, message_size, signature, sig_size);
    } else {
        result = libspdm_pqc_asym_sign(spdm_version, op_code, pqc_asym_algo,
                                       base_hash_algo, context,
                                       message, message_size,
                                       signature, sig_size);
    }
    libspdm_pqc_asym_free(pqc_asym_algo, context);
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
}
#endif

    return result;
}
