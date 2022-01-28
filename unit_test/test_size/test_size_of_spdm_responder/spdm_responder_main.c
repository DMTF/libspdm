/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_responder.h"


/* Disable optimization to avoid code removal with VS2019.*/

#if defined(_MSC_EXTENSIONS)
#pragma optimize("", off)
#endif

void spdm_dispatch(void)
{
    void *spdm_context;
    return_status status;

    spdm_context = spdm_server_init();
    if (spdm_context == NULL) {
        return;
    }

    while (TRUE) {
        status = libspdm_responder_dispatch_message(spdm_context);
        if (status != RETURN_UNSUPPORTED) {
            continue;
        }
    }
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
