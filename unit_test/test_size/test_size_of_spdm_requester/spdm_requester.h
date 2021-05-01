/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_REQUESTER_H__
#define __SPDM_REQUESTER_H__

#include <base.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <library/malloclib.h>

return_status do_authentication_via_spdm(IN void *spdm_context);

return_status do_session_via_spdm(IN void *spdm_context);

void *spdm_client_init(void);

#endif