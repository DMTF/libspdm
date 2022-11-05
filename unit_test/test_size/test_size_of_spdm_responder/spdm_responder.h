/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#ifndef __SPDM_RESPONDER_H__
#define __SPDM_RESPONDER_H__

#include "hal/base.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/malloclib.h"
#include "internal/hal/debuglib_internal.h"
#include "hal/library/memlib.h"

void *spdm_server_init(void);

#endif
