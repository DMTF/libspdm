/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef SLOT_MANAGEMENT_INTERNAL_H
#define SLOT_MANAGEMENT_INTERNAL_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/* Sample-internal value used in the certificate NVM file name to indicate the legacy
 * SET_CERTIFICATE store (no Bank addressing). BankIDs are 0..239 per DSP0274, so 0xFF never
 * collides with a real Bank. This is a sample implementation detail and is intentionally NOT part
 * of the public HAL: integrators express "no Bank" with a NULL bank_id pointer. */
#define LIBSPDM_SLOT_MANAGEMENT_SAMPLE_NVM_LEGACY_BANK 0xFF

#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP || LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/**
 * Classify a SLOT_MANAGEMENT SetCertificate Bank for the sample's certificate store.
 *
 * Resolves, for the addressed Bank, (1) whether the Bank exists, and (2) whether it is the Bank
 * currently selected by the negotiated algorithm. The selected Bank's certificate chain is the
 * one GET_CERTIFICATE / GET_DIGESTS / CHALLENGE serve, so libspdm_update_local_cert_chain stores
 * it in the legacy (no-BankID) NVM file and refreshes the in-memory local_cert_chain_provision,
 * exactly like the base SET_CERTIFICATE flow. A non-selected Bank is stored in its own Bank-keyed
 * NVM file and is not reflected in the SPDM context.
 *
 * @param[in]   spdm_context   A pointer to the SPDM context.
 * @param[in]   bank_id        The Bank addressed by the SetCertificate request.
 * @param[out]  is_selected    On success, true if the Bank is the currently selected Bank.
 *
 * @retval true   The Bank exists; *is_selected is set.
 * @retval false  Unknown Bank.
 **/
bool libspdm_slot_management_sample_classify_bank(
    void *spdm_context, uint8_t bank_id, bool *is_selected);

#endif /* LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP */

#endif /* SLOT_MANAGEMENT_INTERNAL_H */
