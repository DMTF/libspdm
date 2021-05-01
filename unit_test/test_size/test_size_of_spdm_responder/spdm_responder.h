/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_RESPONDER_H__
#define __SPDM_RESPONDER_H__

#include <base.h>
#include <library/spdm_responder_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <library/malloclib.h>

void *spdm_server_init(void);

#endif