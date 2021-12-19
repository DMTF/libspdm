/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

#include "spdm_unit_test.h"

spdm_test_context_t *m_spdm_test_context;

spdm_test_context_t *get_spdm_test_context(void)
{
    return m_spdm_test_context;
}

void setup_spdm_test_context(IN spdm_test_context_t *spdm_test_context)
{
    m_spdm_test_context = spdm_test_context;
}

int spdm_unit_test_group_setup(void **state)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;

    spdm_test_context = m_spdm_test_context;
    spdm_test_context->spdm_context =
        (void *)malloc(libspdm_get_context_size());
    if (spdm_test_context->spdm_context == NULL) {
        return -1;
    }
    spdm_context = spdm_test_context->spdm_context;
    spdm_test_context->case_id = 0xFFFFFFFF;

    libspdm_init_context(spdm_context);
    libspdm_register_device_io_func(spdm_context,
                     spdm_test_context->send_message,
                     spdm_test_context->receive_message);
    libspdm_register_transport_layer_func(spdm_context,
                       spdm_transport_test_encode_message,
                       spdm_transport_test_decode_message);

    *state = spdm_test_context;
    return 0;
}

int spdm_unit_test_group_teardown(void **state)
{
    spdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    free(spdm_test_context->spdm_context);
    spdm_test_context->spdm_context = NULL;
    spdm_test_context->case_id = 0xFFFFFFFF;
    return 0;
}
