/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "spdm_unit_test.h"

libspdm_test_context_t *m_spdm_test_context;

bool m_send_receive_buffer_acquired = false;
uint8_t m_send_receive_buffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
size_t m_send_receive_buffer_size;

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *max_msg_size = sizeof(m_send_receive_buffer);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, size_t *max_msg_size, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *max_msg_size = sizeof(m_send_receive_buffer);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

libspdm_test_context_t *libspdm_get_test_context(void)
{
    return m_spdm_test_context;
}

void libspdm_setup_test_context(libspdm_test_context_t *spdm_test_context)
{
    m_spdm_test_context = spdm_test_context;
}

int libspdm_unit_test_group_setup(void **state)
{
    libspdm_test_context_t *spdm_test_context;
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
    spdm_test_context->scratch_buffer_size =
        libspdm_get_sizeof_required_scratch_buffer(spdm_context);
    spdm_test_context->scratch_buffer = (void *)malloc(spdm_test_context->scratch_buffer_size);

    libspdm_register_device_io_func(spdm_context,
                                    spdm_test_context->send_message,
                                    spdm_test_context->receive_message);
    libspdm_register_transport_layer_func(spdm_context,
                                          libspdm_transport_test_encode_message,
                                          libspdm_transport_test_decode_message,
                                          libspdm_transport_test_get_header_size);
    libspdm_register_device_buffer_func(spdm_context,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);
    libspdm_set_scratch_buffer (spdm_context,
                                spdm_test_context->scratch_buffer,
                                spdm_test_context->scratch_buffer_size);

    *state = spdm_test_context;
    return 0;
}

int libspdm_unit_test_group_teardown(void **state)
{
    libspdm_test_context_t *spdm_test_context;

    spdm_test_context = *state;
    free(spdm_test_context->spdm_context);
    free(spdm_test_context->scratch_buffer);
    spdm_test_context->spdm_context = NULL;
    spdm_test_context->case_id = 0xFFFFFFFF;
    return 0;
}
