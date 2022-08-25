/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

#if LIBSPDM_ENABLE_MSG_LOG
void libspdm_init_msg_log (void *context, void *msg_buffer, size_t msg_buffer_size)
{
    libspdm_context_t *spdm_context;

    LIBSPDM_ASSERT((context != NULL) && (msg_buffer != NULL));
    LIBSPDM_ASSERT(msg_buffer_size != 0);

    spdm_context = context;
    spdm_context->msg_log.buffer = msg_buffer;
    spdm_context->msg_log.buffer_size = msg_buffer_size;
    spdm_context->msg_log.offset = 0;
    spdm_context->msg_log.mode = 0;
    spdm_context->msg_log.status = 0;
}

void libspdm_set_msg_log_mode (void *context, uint32_t mode)
{
    libspdm_context_t *spdm_context;

    LIBSPDM_ASSERT(context != NULL);

    spdm_context = context;
    spdm_context->msg_log.mode = mode;
}

uint32_t libspdm_get_msg_log_status (void *context)
{
    libspdm_context_t *spdm_context;

    LIBSPDM_ASSERT(context != NULL);

    spdm_context = context;

    return spdm_context->msg_log.status;
}

size_t libspdm_get_msg_log_size (void *context)
{
    libspdm_context_t *spdm_context;

    LIBSPDM_ASSERT(context != NULL);

    spdm_context = context;

    return spdm_context->msg_log.offset;
}

void libspdm_reset_msg_log (void *context)
{
    libspdm_context_t *spdm_context;

    LIBSPDM_ASSERT(context != NULL);

    spdm_context = context;

    spdm_context->msg_log.offset = 0;
    spdm_context->msg_log.mode = 0;
    spdm_context->msg_log.status = 0;
}
#endif /* LIBSPDM_ENABLE_MSG_LOG */