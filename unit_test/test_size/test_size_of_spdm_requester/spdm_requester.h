/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_REQUESTER_H__
#define __SPDM_REQUESTER_H__

#include "hal/base.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/malloclib.h"

return_status do_authentication_via_spdm(void *spdm_context);

return_status do_session_via_spdm(void *spdm_context);

void *spdm_client_init(void);

#endif
