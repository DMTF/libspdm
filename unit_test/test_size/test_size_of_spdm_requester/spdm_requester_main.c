/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_requester.h"

#if defined(_MSC_EXTENSIONS)
#pragma optimize("", off)
#endif

void spdm_dispatch(void)
{
    void *spdm_context;
    return_status status;

    spdm_context = spdm_client_init();
    if (spdm_context == NULL) {
        return;
    }

    status = do_authentication_via_spdm(spdm_context);
    if (RETURN_ERROR(status)) {
        return;
    }

    status = do_session_via_spdm(spdm_context);
    return;
}

/**
  Main entry point to DXE Core.

  @param  HobStart               Pointer to the beginning of the HOB List from PEI.

  @return This function should never return.

**/
void ModuleEntryPoint(void)
{
    spdm_dispatch();

    return;
}