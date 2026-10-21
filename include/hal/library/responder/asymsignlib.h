/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_ASYMSIGNLIB_H
#define RESPONDER_ASYMSIGNLIB_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "library/spdm_return_status.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP
/**
 * Returns the opaque data in a CHALLENGE_AUTH response.
 *
 * When SPDM 1.2 or later is negotiated, libspdm calls this function only if an OpaqueDataFmt was
 * selected, and the opaque data must use that format, which LIBSPDM_DATA_OTHER_PARAMS_SUPPORT
 * gives. The opaque data should not be larger than SPDM_MAX_OPAQUE_DATA_SIZE. If false is returned
 * then libspdm sends ERROR(Unspecified), so to send no opaque data, return true and set
 * opaque_data_size to 0.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  spdm_version  Indicates the negotiated version.
 *
 * @param  slot_id               Slot ID of the CHALLENGE request.
 * @param  request_context_size  The size, in bytes, of request_context.
 * @param  request_context       If spdm_version is greater than 1.2, then it is a pointer to the
 *                               Context field in the request message, else it is NULL and ignore.
 *
 * @param opaque_data
 * A pointer to a destination buffer whose size, in bytes, is opaque_data_size. The opaque data is
 * copied to this buffer.
 *
 * @param opaque_data_size
 * On input, indicates the size, in bytes, of the destination buffer.
 * On output, indicates the size of the opaque data.
 *
 * @retval true   The opaque data was returned.
 * @retval false  The opaque data could not be returned.
 **/
extern bool libspdm_challenge_opaque_data(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    size_t request_context_size,
    const void *request_context,
    void *opaque_data,
    size_t *opaque_data_size);

#if (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (LIBSPDM_ENABLE_CAPABILITY_ENCAP_CAP) && \
    (LIBSPDM_SEND_CHALLENGE_SUPPORT)
/**
 * Queries whether basic mutual authentication should be initiated or not.
 *
 * @param  spdm_context  A pointer to the SPDM context.
 * @param  spdm_version  Indicates the negotiated version.
 *
 * @param  slot_id               Slot ID of the CHALLENGE request.
 * @param  request_context_size  The size, in bytes, of request_context.
 * @param  request_context       If spdm_version is greater than 1.2, then it is a pointer to the
 *                               Context field in the request message, else it is NULL and ignore.
 *
 * @retval true   Initiate the basic mutual authentication flow.
 * @retval false  Do not initiate the basic mutual authentication flow.
 */
extern bool libspdm_challenge_start_mut_auth(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    size_t request_context_size,
    const void *request_context);
#endif /* (LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP) && (...) */
#endif /* LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP */

/**
 * Sign an SPDM message data.
 *
 * message is the transcript that the signature covers, or its hash if is_data_hash is true. op_code
 * is the code of the message that carries the signature, such as SPDM_CHALLENGE_AUTH,
 * SPDM_KEY_EXCHANGE_RSP or SPDM_MEASUREMENTS. For SPDM 1.2 and later the signature must cover the
 * combined_spdm_prefix that DSP0274 defines, which depends on spdm_version and op_code, followed by
 * the hash of the transcript. libspdm_asym_sign(), libspdm_asym_sign_hash(),
 * libspdm_pqc_asym_sign() and libspdm_pqc_asym_sign_hash() generate such a signature.
 *
 * pqc_asym_algo is the negotiated post-quantum algorithm, or 0 if base_asym_algo is the signing
 * algorithm. On input, sig_size is the signature size of that algorithm, and the signature must
 * have exactly that size, because libspdm reads sig_size back only for debug output.
 *
 * libspdm also calls this function for messages within a session, without identifying the
 * session.
 *
 * @param  spdm_context    A pointer to the SPDM context.
 * @param  spdm_version    Indicates the negotiated version.
 * @param  key_pair_id     Indicates the key_pair_id in multi-key use case.
 *                         It should be 0, if (SPDM version is < 1.3) OR
 *                         ((SPDM version is >= 1.3) AND (LIBSPDM_DATA_MULTI_KEY_CONN_RSP is false))
 * @param  op_code         The code of the message that carries the signature.
 * @param  base_asym_algo  Indicates the signing algorithm.
 * @param  pqc_asym_algo   Indicates the post-quantum signing algorithm.
 * @param  base_hash_algo  Indicates the hash algorithm.
 * @param  is_data_hash    Indicate the message type.
 *                         If true, message hash.
 *                         If false, raw message before hash.
 * @param  message         A pointer to a message to be signed.
 * @param  message_size    The size, in bytes, of the message to be signed.
 * @param  signature       A pointer to a destination buffer to store the signature.
 * @param  sig_size        On input, indicates the size, in bytes, of the destination buffer to
 *                         store the signature.
 *                         On output, indicates the size, in bytes, of the signature in the buffer.
 *
 * @retval true  Signing success.
 * @retval false Signing fail.
 **/
extern bool libspdm_responder_data_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version,
    uint8_t key_pair_id, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t pqc_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size);

#endif /* RESPONDER_ASYMSIGNLIB_H */
