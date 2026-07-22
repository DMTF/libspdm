/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef RESPONDER_SLOT_MGMT_H
#define RESPONDER_SLOT_MGMT_H

#include "hal/base.h"
#include "internal/libspdm_lib_config.h"
#include "industry_standard/spdm.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP

/**
 * configure the specific bank, including the selected algorithm of the Bank
 * and store the information.
 *
 * @param  spdm_context        A pointer to the SPDM context.
 * @param  bank_id             The Bank to configure.
 * @param  select_asym_algo    The asymmetric algorithm to configure for the Bank.
 * @param  select_pqc_asym_algo  The PQC asymmetric algorithm to configure for the Bank.
 *                             At most one of select_asym_algo and select_pqc_asym_algo is set.
 *
 * @retval true  bank configuration successfully stored.
 * @retval false unable to update the new bank information.
 **/
extern bool libspdm_write_slot_management_manage_bank(
    void *spdm_context,
    uint8_t bank_id,
    uint32_t select_asym_algo,
    uint32_t select_pqc_asym_algo);

#endif
#endif
