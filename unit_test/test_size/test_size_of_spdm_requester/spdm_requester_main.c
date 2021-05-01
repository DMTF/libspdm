/** @file
  TPA Core

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_requester.h"

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