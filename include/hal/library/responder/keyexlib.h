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
 * libspdm calls this function only if the KEY_EXCHANGE request has OpaqueData, and then up to three
 * times. The first call has a NULL opaque_data and asks for the size, which can be larger than the
 * final size. If it returns false then libspdm generates its own OpaqueData instead. Otherwise the
 * second and third calls fill opaque_data, and they must return the same data. If either of them
 * returns false then libspdm sends ERROR(Unspecified).
 *
 * The OpaqueData must contain a secured message version selection, which sets the secured message
 * version of the session. When this function generates the OpaqueData, libspdm does not check
 * req_opaque_data, so this function must check it.
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
 * libspdm calls this function only for SPDM 1.4 and later, and only if an OpaqueDataFmt was
 * selected. The opaque data must use that format, which LIBSPDM_DATA_OTHER_PARAMS_SUPPORT gives,
 * and should not be larger than SPDM_MAX_OPAQUE_DATA_SIZE. If false is returned then libspdm sends
 * ERROR(Unspecified), so to send no opaque data, return true and set opaque_data_size to 0.
 *
 * @param  spdm_context            A pointer to the SPDM context.
 * @param  session_id              Secure session identifier.
 * @param  spdm_version            Indicates the negotiated version.
 * @param  req_slot_id             The certificate slot within the FINISH request, or 0 if the
 *                                 request does not include a signature.
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
 * If the return value is not 0 then mandatory_mut_auth must be set. A return value that is not
 * listed below, or an encapsulated variant when the Requester sets PUB_KEY_ID_CAP, makes libspdm
 * send ERROR(Unspecified). If mandatory_mut_auth is true and the Requester does not set
 * MUT_AUTH_CAP, or an encapsulated variant is returned and the Requester does not set ENCAP_CAP,
 * then libspdm sends ERROR(InvalidPolicy), or ERROR(Unspecified) before SPDM 1.3.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  session_id    Secure session identifier.
 * @param  spdm_version  Indicates the negotiated version.
 * @param  slot_id       The certificate slot within the KEY_EXCHANGE request.
 * @param  req_slot_id   The certificate slot within the KEY_EXCHANGE_RSP response. When
 *                       SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED is returned this shall be
 *                       0xF if the Requester's public key was provisioned to the Responder, and
 *                       between 0 and 7 inclusive otherwise. For every other return value it
 *                       shall be 0, as the slot is conveyed by the encapsulated flow.
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
 *         Request mutual authentication without the encapsulated request flow.
 * @retval SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST
 *         Request mutual authentication with the encapsulated request flow.
 * @retval SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS
 *         Request mutual authentication with the encapsulated request flow, starting with an
 *         implicit GET_DIGESTS request.
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
