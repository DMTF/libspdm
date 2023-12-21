/**
 *  Copyright 2023 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"
#include "internal/libspdm_requester_lib.h"

#if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
int libspdm_requester_vendor_cmds_test_main(void);
int libspdm_requester_vendor_cmds_error_test_main(void);
#endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

int main(void)
{
    int return_value = 0;

    #if LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES
    if (libspdm_requester_vendor_cmds_test_main() != 0) {
        return_value = 1;
    }
    if (libspdm_requester_vendor_cmds_error_test_main() != 0) {
        return_value = 1;
    }
    #endif /* LIBSPDM_ENABLE_VENDOR_DEFINED_MESSAGES */

    return return_value;
}
