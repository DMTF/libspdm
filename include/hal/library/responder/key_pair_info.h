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

typedef struct {
    uint16_t capabilities;
    uint16_t key_usage_capabilities;
    uint16_t current_key_usage;
    uint32_t asym_algo_capabilities;
    uint32_t current_asym_algo;
    uint32_t pqc_asym_algo_capabilities;
    uint32_t current_pqc_asym_algo;
    uint16_t public_key_info_len;
    uint8_t assoc_cert_slot_mask;
    uint8_t public_key_info[SPDM_MAX_PUBLIC_KEY_INFO_LEN];
} libspdm_key_pair_info_t;

#if LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP

/**
 * Apply a validated SET_KEY_PAIR_INFO Operation (Erase/Generate/ChangeParameter) to key_pair_id
 * and write the result to non-volatile memory, similar to libspdm_update_local_cert_chain() for
 * SET_CERTIFICATE.
 *
 * The algorithm fields use the SPDM_KEY_PAIR_ASYM_ALGO_CAP_* and SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_*
 * encodings of SET_KEY_PAIR_INFO. A desired_key_usage, desired_asym_algo or desired_pqc_asym_algo
 * of 0 means that the value does not change, but a desired_assoc_cert_slot_mask of 0 removes every
 * certificate slot association. For the erase operation all four are 0.
 *
 * On input, need_reset is the value of SET_KEY_PAIR_RESET_CAP for SPDM 1.4 and later, and false for
 * SPDM 1.3. If need_reset is true on output then libspdm sends ERROR(ResetRequired), even if the
 * Responder does not set SET_KEY_PAIR_RESET_CAP. Otherwise the implementation must update
 * LIBSPDM_DATA_LOCAL_KEY_PAIR_INFO (via libspdm_set_data()) with the new values before this
 * function returns, because libspdm reads them back. If a reset is required, the implementation
 * must update LIBSPDM_DATA_LOCAL_KEY_PAIR_INFO once the reset has happened. If false is returned
 * then libspdm sends ERROR(OperationFailed).
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
 * @retval true   the operation was applied and written to non-volatile memory successfully.
 * @retval false  the operation could not be applied.
 **/
extern bool libspdm_update_local_key_pair_info(
    void *spdm_context,
    const uint32_t *session_id,
    uint8_t key_pair_id,
    uint8_t operation,
    uint16_t desired_key_usage,
    uint32_t desired_asym_algo,
    uint32_t desired_pqc_asym_algo,
    uint8_t desired_assoc_cert_slot_mask,
    bool *need_reset);

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */

#endif /* RESPONDER_KEY_PAIR_INFO_H */
