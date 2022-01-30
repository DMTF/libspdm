/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_responder_lib.h"
#include "spdm_transport_mctp_lib.h"
#include "industry_standard/mctp.h"
#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"

uintn get_max_buffer_size(void)
{
    return LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
}

void test_spdm_transport_mctp_encode_message(void **State)
{
    spdm_test_context_t *spdm_test_context;
    spdm_context_t *spdm_context;
    uintn transport_message_size;
    uint8_t transport_message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    boolean is_app_message;
    boolean is_requester;
    spdm_test_context = *State;
    spdm_context = spdm_test_context->spdm_context;
    is_requester = spdm_test_context->is_requester;
    is_app_message = FALSE;

    spdm_context->connection_info.connection_state = LIBSPDM_CONNECTION_STATE_AFTER_VERSION;

    transport_message_size = sizeof(transport_message);

    libspdm_transport_mctp_encode_message(spdm_context, NULL, is_app_message, is_requester,
                                          spdm_test_context->test_buffer_size,
                                          spdm_test_context->test_buffer, &transport_message_size,
                                          transport_message);

}

spdm_test_context_t m_spdm_transport_mctp_test_context = {
    SPDM_TEST_CONTEXT_SIGNATURE,
    FALSE,
};

void run_test_harness(IN void *test_buffer, IN uintn test_buffer_size)
{
    void *State;
    uintn record_header_max_size;
    uintn aead_tag_max_size;

    setup_spdm_test_context(&m_spdm_transport_mctp_test_context);

    /* limit the encoding buffer to avoid assert, because the input buffer is controlled by the the libspdm consumer. */
    record_header_max_size = sizeof(mctp_message_header_t) +
                             sizeof(spdm_secured_message_a_data_header1_t) +
                             2 + /* MCTP_SEQUENCE_NUMBER_COUNT */
                             sizeof(spdm_secured_message_a_data_header2_t) +
                             sizeof(spdm_secured_message_cipher_header_t) +
                             32; /* MCTP_MAX_RANDOM_NUMBER_COUNT */
    aead_tag_max_size = LIBSPDM_MAX_AEAD_TAG_SIZE;
    if (test_buffer_size >
        LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - record_header_max_size - aead_tag_max_size) {
        test_buffer_size = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - record_header_max_size -
                           aead_tag_max_size;
    }

    m_spdm_transport_mctp_test_context.test_buffer = test_buffer;
    m_spdm_transport_mctp_test_context.test_buffer_size = test_buffer_size;

    spdm_unit_test_group_setup(&State);

    test_spdm_transport_mctp_encode_message(&State);

    spdm_unit_test_group_teardown(&State);
}
