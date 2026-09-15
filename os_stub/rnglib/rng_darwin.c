/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include <base.h>
#include <stdlib.h>
#include <assert.h>

bool libspdm_get_random_number_64(uint64_t *rand_data)
{
    assert(rand_data != NULL);

    /* arc4random_buf draws from the kernel CSPRNG, is seeded before main, and has no
     * failure mode, so there is no error to report. */
    arc4random_buf(rand_data, sizeof(*rand_data));

    return true;
}
