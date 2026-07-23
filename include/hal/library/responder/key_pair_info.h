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
 * If a reset isn't required (or once it has happened), it is the implementation's responsibility
 * to update LIBSPDM_DATA_LOCAL_KEY_PAIR_INFO (via libspdm_set_data()) so libspdm uses the new
 * value.
 *
 * @param[in,out]  spdm_context                  A pointer to the SPDM context.
 * @param[in]      key_pair_id                   Indicates which key pair ID to update. KeyPairID
 *                                                is 1-based.
 * @param[in]      operation                     SPDM_SET_KEY_PAIR_INFO_*_OPERATION.
 * @param[in]      desired_key_usage             Indicate the desired key usage for the key pair.
 * @param[in]      desired_asym_algo             Indicate the desired asymmetric algorithm.
 * @param[in]      desired_pqc_asym_algo         Indicate the desired PQC asymmetric algorithm.
 * @param[in]      desired_assoc_cert_slot_mask  Indicate the desired certificate slot
 *                                                association.
 * @param[in,out]  need_reset                    On input, the value of SET_KEY_PAIR_RESET_CAP.
 *                                                On output, whether the device needs to be reset
 *                                                to complete the SET_KEY_PAIR_INFO operation.
 *
 * @retval true   the operation was applied and written to non-volatile memory successfully.
 * @retval false  the operation could not be applied.
 **/
extern bool libspdm_update_local_key_pair_info(
    void *spdm_context,
    uint8_t key_pair_id,
    uint8_t operation,
    uint16_t desired_key_usage,
    uint32_t desired_asym_algo,
    uint32_t desired_pqc_asym_algo,
    uint8_t desired_assoc_cert_slot_mask,
    bool *need_reset);

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP */

#endif /* RESPONDER_KEY_PAIR_INFO_H */
