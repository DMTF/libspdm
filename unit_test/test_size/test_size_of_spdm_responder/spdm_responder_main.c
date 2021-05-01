/** @file
  TPA Core

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_responder.h"

void spdm_dispatch(void)
{
	void *spdm_context;
	return_status status;

	spdm_context = spdm_server_init();
	if (spdm_context == NULL) {
		return;
	}

	while (TRUE) {
		status = spdm_responder_dispatch_message(spdm_context);
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