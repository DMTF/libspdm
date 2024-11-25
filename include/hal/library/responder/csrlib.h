/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_CSRLIB_H
#define RESPONDER_CSRLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
/**
 * Generate a PKCS #10 certificate signing request.
 *
 * @param[in]     spdm_context    A pointer to the SPDM context.
 * @param[in]     base_hash_algo  Indicates the hash algorithm.
 * @param[in]     base_asym_algo  Indicates the signing algorithm.
 * @param[in,out] need_reset      On input, indicates the value of CERT_INSTALL_RESET_CAP.
 *                                On output, indicates whether the device needs to be reset (true)
 *                                for the GET_CSR operation to complete.
 * @param[in]      request        A pointer to the SPDM request data.
 * @param[in]      request_size   The size of SPDM request data.
 * @param[in]      requester_info         Requester info used to generate the CSR.
 * @param[in]      requester_info_length  The length, in bytes, of requester_info.
 * @param[in]      opaque_data            Requester opaque data used to generate the CSR.
 * @param[in]      opaque_data_length     The length, in bytes, of opaque_data.
 * @param[in,out]  csr_len                On input, the size, in bytes, of the buffer to store the
 *                                        CSR.
 *                                        On output, the size, in bytes, of the CSR.
 * @param[in,out]  csr_pointer            A pointer to the buffer to store the CSR.
 * @param[in]      is_device_cert_model   If true, the certificate chain is the DeviceCert model.
 *                                        If false, the certificate chain is the AliasCert model.
 * @param[out]     is_busy                If true, indicates that the CSR cannot be generated at
 *                                        this time, but it may be successful in a later call. The
 *                                        function's return value must be false if this parameter is
 *                                        true.
 * @param[out]     unexpected_request     If true, then request is different than the request that
 *                                        triggered a ResetRequired error response. The function's
 *                                        return value must be false if this parameter is true.
 *
 * @retval  true   CSR generated successfully.
 * @retval  false  Failed to generate CSR.
 **/
extern bool libspdm_gen_csr(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    bool is_device_cert_model
#if LIBSPDM_SET_CERT_CSR_PARAMS
    , bool *is_busy, bool *unexpected_request
#endif
    );

/**
 * Generate a PKCS #10 certificate signing request for SPDM versions 1.3 and higher.
 *
 *   Table for parameters and results when device requires a reset to process CSRs.
 *   Only valid if Responder sets CERT_INSTALL_RESET_CAP.
 *
 *   | Overwrite | CSRTrackingTag | Pending CSR | Reset |       Resulting Action       |
 *   |-----------| ---------------|-------------|-------|------------------------------|
 *   |    No     |     0          |      No     |   -   |          Return true         |
 *   |    No     |     0          |      Yes    |   -   | Assert need_reset or is_busy |
 *   |    No     |   Non-0        |   No Match  |   -   |  Assert unexpected_request   |
 *   |    No     |   Non-0        |     Match   | Before|        Assert is_busy        |
 *   |    No     |   Non-0        |     Match   | After |          Return true         |
 *   |    Yes    |     0          |       -     |   -   |       Assert need_reset      |
 *
 * @param[in]     spdm_context    A pointer to the SPDM context.
 * @param[in]     base_hash_algo  Indicates the hash algorithm.
 * @param[in]     base_asym_algo  Indicates the signing algorithm.
 * @param[in,out] need_reset      On input, indicates the value of CERT_INSTALL_RESET_CAP.
 *                                On output, indicates whether the device needs to be reset (true)
 *                                for the GET_CSR operation to complete. If true then
 *                                req_csr_tracking_tag, on output, must be non-zero.
 * @param[in]      request        A pointer to the SPDM request data.
 * @param[in]      request_size   The size of SPDM request data.
 * @param[in]      requester_info         Requester info used to generate the CSR.
 * @param[in]      requester_info_length  The length, in bytes, of requester_info.
 * @param[in]      opaque_data            Requester opaque data used to generate the CSR.
 * @param[in]      opaque_data_length     The length, in bytes, of opaque_data.
 * @param[in,out]  csr_len                On input, the size, in bytes, of the buffer to store the
 *                                        CSR.
 *                                        On output, the size, in bytes, of the CSR.
 * @param[in,out]  csr_pointer            A pointer to the buffer to store the CSR.
 * @param[in]      req_cert_model         Indicates the desired certificate model of the CSR.
 * @param[in,out]  req_csr_tracking_tag   On input, the CSRTrackingTag of the GET_CSR request.
 *                                        On output, the CSRTrackingTag for the ResetRequired error.
 * @param[in]      req_key_pair_id        Indicates the desired key pair associated with the CSR.
 * @param[in]      overwrite              If set, the Responder shall stop processing any existing
 *                                        GET_CSR request and overwrite it with this request.
 * @param[out]     is_busy                If true, indicates that the CSR cannot be generated at
 *                                        this time, but it may be successful in a later call. The
 *                                        function's return value must be false if this parameter is
 *                                        true.
 * @param[out]     unexpected_request     If true, then request is different than the request that
 *                                        triggered a ResetRequired error response. The function's
 *                                        return value must be false if this parameter is true.
 *
 * @retval  true   CSR generated successfully.
 * @retval  false  Failed to generate CSR.
 **/

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX
extern bool libspdm_gen_csr_ex(
#if LIBSPDM_HAL_PASS_SPDM_CONTEXT
    void *spdm_context,
#endif
    uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
    const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length,
    size_t *csr_len, uint8_t *csr_pointer,
    uint8_t req_cert_model,
    uint8_t *req_csr_tracking_tag,
    uint8_t req_key_pair_id,
    bool overwrite
#if LIBSPDM_SET_CERT_CSR_PARAMS
    , bool *is_busy, bool *unexpected_request
#endif
    );
#endif /*LIBSPDM_ENABLE_CAPABILITY_CSR_CAP_EX*/
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

#endif /* RESPONDER_CSRLIB_H */
