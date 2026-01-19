/**
 *  Copyright Notice:
 *  Copyright 2024 DMTF. All rights reserved.
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
#include "hal/library/cryptlib/cryptlib_tpm.h"
#include "internal/libspdm_common_lib.h"
#include "keys.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
bool libspdm_requester_data_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t key_pair_id, uint8_t op_code,
    uint16_t req_base_asym_alg, uint32_t req_pqc_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context = NULL;
    bool result = false;

    libspdm_debug_print(SPDM_ERROR, "Loading TPM device");
    libspdm_tpm_device_init();
    result = libspdm_tpm_get_private_key(TPM_REQU_HANDLE, &context);
    if (!result){
        libspdm_debug_print(SPDM_ERROR, "Failed to load requester handle");
        return false;
    }

    if (is_data_hash){
        result = libspdm_req_asym_sign_hash(
            spdm_version, op_code, req_base_asym_alg, base_hash_algo, context,
            message, message_size, signature, sig_size);
    } else {
        result = libspdm_req_asym_sign(spdm_version, op_code, req_base_asym_alg,
                                       base_hash_algo, context, message,
                                       message_size, signature, sig_size);
    }
    libspdm_asym_free(req_base_asym_alg, context);

    return result;
}
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (...) */

bool libspdm_responder_data_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t key_pair_id, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context = NULL;
    bool result = false;

    libspdm_tpm_device_init();
    result = libspdm_tpm_get_private_key(TPM_RESP_HANDLE, &context);
    if (!result){
        libspdm_debug_print(SPDM_ERROR, "Failed to load responder handle");
        return false;
    }

    if (is_data_hash){
        result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo,
                                        base_hash_algo, context, message,
                                        message_size, signature, sig_size);
    } else {
        result =
            libspdm_asym_sign(spdm_version, op_code, base_asym_algo, base_hash_algo,
                              context, message, message_size, signature, sig_size);
    }
    libspdm_asym_free(base_asym_algo, context);

    return result;
}
