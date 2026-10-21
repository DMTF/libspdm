/**
 *  Copyright Notice:
 *  Copyright 2024-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_KEY_PAIR_INFO_H
#define RESPONDER_KEY_PAIR_INFO_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP

/**
 * read the key pair info of the key_pair_id.
 *
 * total_key_pairs is the TotalKeyPairs field of the KEY_PAIR_INFO response, and it is a fixed
 * number per SPDM connection. It shall always be set, including on the failure path (set it before
 * any other validation), because the Responder uses it to range-check key_pair_id. A device with no
 * key pairs shall set it to 0.
 *
 * The algorithm fields use the SPDM_KEY_PAIR_ASYM_ALGO_CAP_* and SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_*
 * encodings of KEY_PAIR_INFO, not those of BaseAsymAlgo and PqcAsymAlgo. public_key_info is the DER
 * encoding of the AlgorithmIdentifier of the public key, and public_key_info_len is 0 if the key
 * pair has not been generated.
 *
 * @param  spdm_context                A pointer to the SPDM context.
 * @param  session_id                  Indicates the session in which the request was received.
 *                                     If NULL then the request was not received in a session.
 * @param  key_pair_id                 Indicate which key pair ID's information to retrieve.
 * @param  total_key_pairs             Indicate the total number of key pairs on the Responder.
 * @param  capabilities                Indicate the capabilities of the requested key pairs.
 * @param  key_usage_capabilities      Indicate the key usages the responder allows.
 * @param  current_key_usage           Indicate the currently configured key usage for the requested
 *                                     key pairs ID.
 * @param  asym_algo_capabilities      Indicate the asymmetric algorithms the Responder supports for
 *                                     this key pair ID.
 * @param  current_asym_algo           Indicate the currently configured asymmetric algorithm for
 *                                     this key pair ID.
 * @param  pqc_asym_algo_capabilities  Indicate the PQC asymmetric algorithms the Responder supports
 *                                     for this key pair ID.
 * @param  current_pqc_asym_algo       Indicate the currently configured PQC asymmetric algorithm
 *                                     for this key pair ID.
 * @param  assoc_cert_slot_mask        This field is a bit mask representing the currently
 *                                     associated certificate slots.
 * @param  public_key_info_len         On input, indicate the size in bytes of the destination
 *                                     buffer to store.
 *                                     On output, indicate the size in bytes of the public_key_info.
 *                                     It can be NULL, if public_key_info is not required.
 * @param  public_key_info             A pointer to a destination buffer to store the
 *                                     public_key_info.
 *                                     It can be NULL, if public_key_info is not required.
 *
 * @retval true  get key pair info successfully.
 * @retval false get key pair info failed. total_key_pairs shall still be set on this path so the
 *               caller can distinguish an invalid key_pair_id (0 or > total_key_pairs ->
 *               INVALID_REQUEST) from another read failure (-> UNSPECIFIED).
 **/
extern bool libspdm_read_key_pair_info(
    void *spdm_context,
    const uint32_t *session_id,
    uint8_t key_pair_id,
    uint8_t *total_key_pairs,
    uint16_t *capabilities,
    uint16_t *key_usage_capabilities,
    uint16_t *current_key_usage,
    uint32_t *asym_algo_capabilities,
    uint32_t *current_asym_algo,
    uint32_t *pqc_asym_algo_capabilities,
    uint32_t *current_pqc_asym_algo,
    uint8_t *assoc_cert_slot_mask,
    uint16_t *public_key_info_len,
    uint8_t *public_key_info);
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP
/**
 * write the key pair info of the key_pair_id.
 *
 * The algorithm fields use the SPDM_KEY_PAIR_ASYM_ALGO_CAP_* and SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_*
 * encodings of SET_KEY_PAIR_INFO. A desired_key_usage, desired_asym_algo or desired_pqc_asym_algo
 * of 0 means that the value does not change, but a desired_assoc_cert_slot_mask of 0 removes every
 * certificate slot association. For the erase operation all four are 0.
 *
 * On input, need_reset is the value of SET_KEY_PAIR_RESET_CAP for SPDM 1.4 and later, and false for
 * SPDM 1.3. If need_reset is true on output then libspdm sends ERROR(ResetRequired), even if the
 * Responder does not set SET_KEY_PAIR_RESET_CAP. Otherwise libspdm_read_key_pair_info() must return
 * the new values as soon as this function returns, because libspdm reads them back. If false is
 * returned then libspdm sends ERROR(OperationFailed).
 *
 * @param  spdm_context                  A pointer to the SPDM context.
 * @param  session_id                    Indicates the session in which the request was received.
 *                                       If NULL then the request was not received in a session.
 * @param  key_pair_id                   Indicate which key pair ID's information to write.
 * @param  operation                     Set key pair info operation: change/erase/generate.
 * @param  desired_key_usage             Indicate the desired key usage for the requested key pair
 *                                       ID.
 * @param  desired_asym_algo             Indicate the desired asymmetric algorithm for the requested
 *                                       key pair ID.
 * @param  desired_pqc_asym_algo         Indicate the desired PQC asymmetric algorithm for the
 *                                       requested key pair ID.
 * @param  desired_assoc_cert_slot_mask  Indicate the desired certificate slot association for the
 *                                       requested key pair ID.
 * @param  need_reset                    On input, indicates whether the change needs a reset.
 *                                       On output, indicates whether the device needs to be reset
 *                                       to complete the set_key_pair_info.
 *
 * @retval true  set key pair info successfully.
 * @retval false set key pair info failed.
 **/
extern bool libspdm_write_key_pair_info(
    void *spdm_context,
    const uint32_t *session_id,
    uint8_t key_pair_id,
    uint8_t operation,
    uint16_t desired_key_usage,
    uint32_t desired_asym_algo,
    uint32_t desired_pqc_asym_algo,
    uint8_t desired_assoc_cert_slot_mask,
    bool * need_reset);
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */

#endif /* RESPONDER_KEY_PAIR_INFO_H */
