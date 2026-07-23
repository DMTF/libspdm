/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "internal/libspdm_device_secret_lib.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/responder/slot_mgmt.h"

#if LIBSPDM_ENABLE_CAPABILITY_SLOT_MGMT_CAP
bool libspdm_write_slot_management_manage_bank(
    void *spdm_context,
    uint8_t bank_id,
    uint32_t select_asym_algo,
    uint32_t select_pqc_asym_algo)
{
    /* It's our responsibility to store the updates
     * select_asym_algo and select_pqc_asym_algo values into non-volatile
     * storage, so that when libspdm is started again the values are preserved.
     *
     * We don't actually do that though, as this is just a sample device, so just
     * pretend we did. libspdm will update it's internal copy while running, so
     * everything will work fine.
     */

    return true;
}
#endif
