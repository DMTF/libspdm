/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_requester.h"

return_status do_session_via_spdm(IN void *spdm_context)
{
	return_status status;
	uint32 session_id;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];

	heartbeat_period = 0;
	zero_mem(measurement_hash, sizeof(measurement_hash));
	status = spdm_start_session(
		spdm_context,
		FALSE, // KeyExchange
		SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, 0,
		&session_id, &heartbeat_period, measurement_hash);
	if (RETURN_ERROR(status)) {
		DEBUG((DEBUG_ERROR, "spdm_start_session - %r\n", status));
		return status;
	}

	//
	// TBD - Set key
	//

	status = spdm_stop_session(spdm_context, session_id, 0);
	if (RETURN_ERROR(status)) {
		DEBUG((DEBUG_ERROR, "spdm_stop_session - %r\n", status));
		return status;
	}

	return status;
}