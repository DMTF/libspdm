/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
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
#include "library/debuglib.h"
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_common_lib.h"
#include "keys.h"

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) || (LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP)
static const char *get_requester_key_handle(uint8_t slot_id)
{
    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0
    case 0:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_1
    case 1:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_1;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_2
    case 2:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_2;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_3
    case 3:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_3;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_4
    case 4:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_4;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_5
    case 5:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_5;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_6
    case 6:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_6;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_7
    case 7:
        return LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_7;
#endif
    default:
        return NULL;
    }
}

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
    const char *key_handle = NULL;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Loading TPM device"));
    if (!libspdm_tpm_device_init()) {
        return false;
    }

    key_handle = get_requester_key_handle(key_pair_id);
    if (key_handle == NULL) {
        key_handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0;
    }

    result = libspdm_tpm_get_pvt_key_handle(key_handle, &context);
    if (!result){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to load requester handle %s\n", key_handle));
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

static const char *get_responder_key_handle(uint8_t slot_id)
{
    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0
    case 0:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_1
    case 1:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_1;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_2
    case 2:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_2;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_3
    case 3:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_3;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_4
    case 4:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_4;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_5
    case 5:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_5;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_6
    case 6:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_6;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_7
    case 7:
        return LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_7;
#endif
    default:
        return NULL;
    }
}

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
    const char *key_handle = NULL;

    if (!libspdm_tpm_device_init()) {
        return false;
    }

    key_handle = get_responder_key_handle(key_pair_id);
    if (key_handle == NULL) {
        key_handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0;
    }

    result = libspdm_tpm_get_pvt_key_handle(key_handle, &context);
    if (!result){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to load responder handle %s\n", key_handle));
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
