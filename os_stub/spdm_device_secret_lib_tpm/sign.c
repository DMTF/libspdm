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
#include "library/debuglib.h"
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "internal/libspdm_common_lib.h"
#include "keys.h"

static bool libspdm_tpm_get_requester_handle_by_slot(uint8_t slot_id, const char **handle)
{
    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0
    case 0:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_0;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_1
    case 1:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_1;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_2
    case 2:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_2;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_3
    case 3:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_3;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_4
    case 4:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_4;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_5
    case 5:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_5;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_6
    case 6:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_6;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_7
    case 7:
        *handle = LIBSPDM_TPM_HANDLE_REQUESTER_HANDLE_SLOT_7;
        return true;
#endif
    default:
        return false;
    }
}

static bool libspdm_tpm_get_responder_handle_by_slot(uint8_t slot_id, const char **handle)
{
    switch (slot_id) {
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0
    case 0:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_0;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_1
    case 1:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_1;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_2
    case 2:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_2;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_3
    case 3:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_3;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_4
    case 4:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_4;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_5
    case 5:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_5;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_6
    case 6:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_6;
        return true;
#endif
#ifdef LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_7
    case 7:
        *handle = LIBSPDM_TPM_HANDLE_RESPONDER_HANDLE_SLOT_7;
        return true;
#endif
    default:
        return false;
    }
}

static const char *libspdm_tpm_get_requester_handle_by_key_pair_id(void *spdm_context,
                                                                   uint32_t base_asym_algo,
                                                                   uint32_t pqc_asym_algo,
                                                                   uint8_t key_pair_id)
{
    const char *handle;

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
    if (key_pair_id != 0) {
        libspdm_context_t *context;
        uint8_t slot_id;

        context = spdm_context;
        if (context != NULL) {
            for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
                if (((LIBSPDM_TPM_REQUESTER_SUPPORTED_SLOT_MASK & (1u << slot_id)) != 0) &&
                    (context->local_context.local_key_pair_id[slot_id] == key_pair_id) &&
                    libspdm_tpm_get_requester_handle_by_slot(slot_id, &handle)) {
                    return handle;
                }
            }
        }

        for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
            if (((LIBSPDM_TPM_REQUESTER_SUPPORTED_SLOT_MASK & (1u << slot_id)) != 0) &&
                (key_pair_id == libspdm_get_key_pair_id_by_slot(base_asym_algo, pqc_asym_algo,
                                                                slot_id)) &&
                libspdm_tpm_get_requester_handle_by_slot(slot_id, &handle)) {
                return handle;
            }
        }

        return NULL;
    }
#endif

    if (!libspdm_tpm_get_requester_handle_by_slot(0, &handle)) {
        return NULL;
    }
    return handle;
}

static const char *libspdm_tpm_get_responder_handle_by_key_pair_id(void *spdm_context,
                                                                   uint32_t base_asym_algo,
                                                                   uint32_t pqc_asym_algo,
                                                                   uint8_t key_pair_id)
{
    const char *handle;

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP
    if (key_pair_id != 0) {
        libspdm_context_t *context;
        uint8_t slot_id;

        context = spdm_context;
        if (context != NULL) {
            for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
                if (((LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK & (1u << slot_id)) != 0) &&
                    (context->local_context.local_key_pair_id[slot_id] == key_pair_id) &&
                    libspdm_tpm_get_responder_handle_by_slot(slot_id, &handle)) {
                    return handle;
                }
            }
        }

        for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
            if (((LIBSPDM_TPM_RESPONDER_SUPPORTED_SLOT_MASK & (1u << slot_id)) != 0) &&
                (key_pair_id == libspdm_get_key_pair_id_by_slot(base_asym_algo, pqc_asym_algo,
                                                                slot_id)) &&
                libspdm_tpm_get_responder_handle_by_slot(slot_id, &handle)) {
                return handle;
            }
        }

        return NULL;
    }
#endif

    if (!libspdm_tpm_get_responder_handle_by_slot(0, &handle)) {
        return NULL;
    }
    return handle;
}

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
    const char *handle;

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "Loading TPM device"));
    if (req_pqc_asym_alg != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "TPM requester PQC signing is not supported\n"));
        return false;
    }
    if (!libspdm_tpm_device_init()) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to initialize TPM device"));
        return false;
    }
    handle = libspdm_tpm_get_requester_handle_by_key_pair_id(spdm_context, req_base_asym_alg,
                                                             req_pqc_asym_alg, key_pair_id);
    if (handle == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to resolve requester key handle"));
        return false;
    }
    result = libspdm_tpm_get_pvt_key_handle(handle, &context);
    if (!result){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to load requester handle"));
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
    const char *handle;

    if (pqc_asym_algo != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "TPM responder PQC signing is not supported\n"));
        return false;
    }
    if (!libspdm_tpm_device_init()) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to initialize TPM device"));
        return false;
    }
    handle = libspdm_tpm_get_responder_handle_by_key_pair_id(spdm_context, base_asym_algo,
                                                             pqc_asym_algo, key_pair_id);
    if (handle == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to resolve responder key handle"));
        return false;
    }
    result = libspdm_tpm_get_pvt_key_handle(handle, &context);
    if (!result){
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "Failed to load responder handle"));
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
