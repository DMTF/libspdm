/**
 *  Copyright Notice:
 *  Copyright 2021-2025 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#include "spdm_device_secret_lib_internal.h"

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size,
    uint8_t *out, size_t out_size)
{
    return false;
}

bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size, uint8_t *out,
    size_t out_size)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment(void *spdm_context)
{
    return false;
}

bool libspdm_write_certificate_to_nvm(
    void *spdm_context,
    uint8_t slot_id, const void * cert_chain,
    size_t cert_chain_size,
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    bool *need_reset, bool *is_busy)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
bool libspdm_gen_csr(
    void *spdm_context,
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    bool is_device_cert_model,
    bool *is_busy, bool *unexpected_request)
{
    return false;
}

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
bool libspdm_gen_csr_ex(
    void *spdm_context,
    uint32_t base_hash_algo, uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    uint8_t req_cert_model,
    uint8_t *csr_tracking_tag,
    uint8_t req_key_pair_id,
    bool overwrite,
    bool *is_busy, bool *unexpected_request)
{
    return false;
}
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP
bool libspdm_event_get_types(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    void *supported_event_groups_list,
    uint32_t *supported_event_groups_list_len,
    uint8_t *event_group_count)
{
    return false;
}

bool libspdm_event_subscribe(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    uint8_t subscribe_type,
    uint8_t subscribe_event_group_count,
    uint32_t subscribe_list_len,
    const void *subscribe_list)
{
    return false;
}

bool libspdm_generate_event_list(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint32_t session_id,
    uint32_t *event_count,
    size_t *events_list_size,
    void *events_list)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_EVENT_CAP */


#ifdef LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP
libspdm_return_t libspdm_generate_device_endpoint_info(
    void *spdm_context,
    uint8_t sub_code,
    uint8_t request_attributes,
    uint32_t *endpoint_info_size,
    void *endpoint_info)
{
    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}
#endif /* #if LIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP */
