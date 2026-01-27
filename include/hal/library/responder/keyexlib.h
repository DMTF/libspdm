/**
 *  Copyright Notice:
 *  Copyright 2025-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_KEYEXLIB_H
#define RESPONDER_KEYEXLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP

/**
 * Generates the OpaqueData field of the KEY_EXCHANGE_RSP message.
 *
 * @param  spdm_context               A pointer to the SPDM context.
 * @param  spdm_version               Indicates the negotiated version.
 * @param  measurement_hash_type      The measurement hash type in the KEY_EXCHANGE request.
 * @param  slot_id                    The certificate slot within the KEY_EXCHANGE request.
 * @param  session_policy             Policy for the session. A bitmask whose values are
 *                                    SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_*.
 * @param  req_opaque_data            The OpaqueData field in the KEY_EXCHANGE request.
 * @param  req_opaque_data_size       Size, in bytes, of req_opaque_data.
 * @param  opaque_data                The buffer to store the OpaqueData field in the
 *                                    KEY_EXCHANGE_RSP response.
 * @param  opaque_data_size           On input, size, in bytes, of the opaque_data buffer.
 *                                    On output, size, in bytes, of copied data in the
 *                                    opaque_data buffer.
 *
 * @retval true   OpaqueData field is generated successfully.
 *                If return true, responder will not generate any opaque data,
 *                including secured message version.
 * @retval false  OpaqueData field generation failed.
 */
extern bool libspdm_key_exchange_rsp_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t measurement_hash_type,
    uint8_t slot_id,
    uint8_t session_policy,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size);

/**
 * Processes the OpaqueData field of the FINISH_RSP message.
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  session_id              Secure session identifier.
 * @param  spdm_version            Indicates the negotiated version.
 * @param  req_slot_id             The certificate slot within the FINISH reuest.
 * @param  req_opaque_data         The OpaqueData field in the FINISH request.
 * @param  req_opaque_data_size    Size, in bytes, of req_opaque_data.
 * @param  opaque_data             The buffer to store the OpaqueData field in the FINISH_RSP response.
 * @param  opaque_data_size        On input, size, in bytes, of the opaque_data buffer.
 *                                 On output, size, in bytes, of copied data in the opaque_data buffer.
 *
 * @retval true   OpaqueData field is processed successfully.
 * @retval false  OpaqueData field processing failed.
 */
extern bool libspdm_finish_rsp_opaque_data(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t req_slot_id,
    const void *req_opaque_data,
    size_t req_opaque_data_size,
    void *opaque_data,
    size_t *opaque_data_size);

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
/**
 * Queries whether session-based mutual authentication should be initiated or not.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Secure session identifier.
 * @param  spdm_version  Indicates the negotiated version.
 * @param  slot_id       The certificate slot within the KEY_EXCHANGE request.
 * @param  req_slot_id   The certificate slot within the KEY_EXCHANGE_RSP response.
 *                       This value can be non-zero only when
 *                       SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED is returned.
 *
 * @param  session_policy  Policy for the session. A bitmask whose values are
 *                         SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_*.
 *
 * @param  opaque_data_length  Size, in bytes, of opaque_data.
 * @param  opaque_data         The KEY_EXCHANGE OpaqueData field. Its value is NULL if value of
 *                             opaque_data_length is 0.
 * @param  mandatory_mut_auth  If true, then mutual authentication must be completed, and libspdm
 *                             will return an error to the Requester if the Requester does not
 *                             support mutual authentication. If false, and Requester does not
 *                             support mutual authentication, then the session will still be
 *                             established.
 *
 * @retval 0  Do not initiate the session-based mutual authentication flow.
 * @retval SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED
 * @retval SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST
 * @retval SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS
 */
extern uint8_t libspdm_key_exchange_start_mut_auth(
    void *spdm_context,
    uint32_t session_id,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *req_slot_id,
    uint8_t session_policy,
    size_t opaque_data_length,
    const void *opaque_data,
    bool *mandatory_mut_auth);
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */
#endif /* LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP */

#endif /* RESPONDER_KEYEXLIB_H */
